//! PB3 `mssig(tag)` command.
//!
//! `squeeze_*` functions essentially implement the following PB3 message:
//!
//! ```pb3
//! message Mssig {
//!     commit;
//!     squeeze external tryte tag[78];
//!     mssig(tag) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `tag` -- 78 trytes of hash value to be signed, it is squeezed externally and is not present in the encoded message.
//!
//! * `sig` -- MSS signature generated with the private key provided to `wrap` operation.
//! The verification public key during `unwrap` operation is determined implicitly.
//!
//! Note, in order to simplify public key verification (ie. to determine trust to the key)
//! link to the public key's proof can be added as an explicit field. To be discussed.

use crate::mss;
use crate::pb3::err::{Err, guard, Result};
use crate::spongos::{Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// Size of `mssig` field depends on MSS MT height.
pub fn sizeof_mssig(sk: &mss::PrivateKey) -> usize {
    mss::sig_size(sk.height())
}

/// Sign `tag` with private key `sk` and put it into `b`.
pub fn wrap_mssig(tag: TritConstSlice, sk: &mss::PrivateKey, _s: &mut Spongos, b: &mut TritMutSlice) {
    let n = sizeof_mssig(sk);
    assert!(n <= b.size());
    let sig = b.advance(n);
    sk.sign(tag, sig);
    //TODO: Should sig be `absorb`ed into the spongos? To be discussed.
    //_s.absorb(sig.as_const());
    //TODO: Add link to the public key proof message.
}

/// Recover public key from signature in `b` for `tag`.
pub fn unwrap_mssig_recover(tag: TritConstSlice, _s: &mut Spongos, b: &mut TritConstSlice) -> Result<mss::PublicKey> {
    let mut apk = Trits::zero(mss::PK_SIZE);
    let sig_size = mss::recover(apk.mut_slice(), tag, *b).ok_or(Err::BadValue)?;
    let _sig = b.advance(sig_size);
    //_s.absorb(_sig);
    Ok(mss::PublicKey{ pk: apk })
}

/// Recover public key from signature in `b` for `tag` and verify against public key `pk`.
pub fn unwrap_mssig_verify(tag: TritConstSlice, pk: &mss::PublicKey, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    let apk = unwrap_mssig_recover(tag, s, b)?;
    guard(apk == *pk, Err::MssVerifyFailed)?;
    Ok(())
}

/// Commit spongos state `s` and squeeze to-be-signed hash value from it.
///
/// ```pb3
/// commit;
/// squeeze external tryte tag[78];
/// ```
pub fn squeeze_mss_hash(s: &mut Spongos) -> Trits {
    let mut tag = Trits::zero(mss::HASH_SIZE);
    s.commit();
    s.squeeze(tag.mut_slice());
    tag
}

/// Squeeze tag and sign it with MSS private key.
pub fn squeeze_wrap_mssig(sk: &mss::PrivateKey, s: &mut Spongos, b: &mut TritMutSlice) {
    let tag = squeeze_mss_hash(s);
    wrap_mssig(tag.slice(), sk, s, b);
}

/// Squeeze tag and recover MSS public key.
pub fn squeeze_unwrap_mssig_recover(s: &mut Spongos, b: &mut TritConstSlice) -> Result<mss::PublicKey> {
    let tag = squeeze_mss_hash(s);
    unwrap_mssig_recover(tag.slice(), s, b)
}

/// Squeeze tag and verify MSS signature.
pub fn squeeze_unwrap_mssig_verify(pk: &mss::PublicKey, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    let tag = squeeze_mss_hash(s);
    unwrap_mssig_verify(tag.slice(), pk, s, b)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::channel::msg;
    use crate::prng;

    #[test]
    fn squeeze_wrap_unwrap() {
        // secrets, nonces
        let prng_key = Trits::from_str("PRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKE").unwrap();
        let mss_nonce = Trits::from_str("MSSNONCE").unwrap();

        // secret objects
        let prng = prng::PRNG::init(prng_key.slice());
        let d = 0;
        let mss_sk = mss::PrivateKey::gen(&prng, d, mss_nonce.slice());
        let mss_pk = mss_sk.public_key();

        // message
        let data = Trits::from_str("DATADATADATADATADATADATA").unwrap();
        let n = super::sizeof_mssig(&mss_sk);
        let mut buf = Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            s.absorb_trits(&data);
            let mut b = buf.mut_slice();
            super::squeeze_wrap_mssig(&mss_sk, &mut s, &mut b);
        }

        // unwrap
        {
            let mut s = Spongos::init();
            s.absorb_trits(&data);
            let mut b = buf.slice();
            let r = super::squeeze_unwrap_mssig_verify(&mss_pk, &mut s, &mut b);
            assert_eq!(Ok(()), r);
        }
    }
}
