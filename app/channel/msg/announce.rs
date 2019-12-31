//! `Announce` message content. This is the initial message of the Channel application instance.
//! It announces channel owner's public keys: MSS and possibly NTRU, and is similar to
//! self-signed certificate in a conventional PKI.
//! 
//! ```pb3
//! message Announce {
//!     absorb tryte msspk[81];
//!     absorb oneof {
//!         null empty = 0;
//!         tryte ntrupk[3072] = 1;
//!     }
//!     commit;
//!     squeeze external tryte tag[78];
//!     mssig(tag) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `msspk` -- channel owner's MSS public key.
//!
//! * `empty` -- signifies absence of owner's NTRU public key.
//!
//! * `ntrupk` -- channel owner's NTRU public key.
//!
//! * `tag` -- hash-value to be signed.
//!
//! * `sig` -- signature of `tag` field produced with the MSS private key corresponding to `msspk`.
//!

use crate::app::core::{APPINST_SIZE, AppInst, MSGID_SIZE, MsgId};
use crate::mss;
use crate::ntru;
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::prng::{self, PRNG};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// Type of `Announce` message content.
pub const TYPE: &'static str = "MAM9CHANNEL9ANNOUNCE";

/// Size of `Announce` message content.
///
/// # Arguments
///
/// * `mss_sk` -- channel owner's MSS private key.
///
/// * `has_ntru_pk` -- whether channel owner has and includes NTRU private key in the message.
pub fn sizeof(mss_sk: &mss::PrivateKey, has_ntru_pk: bool) -> usize {
    0
    // absorb tryte msspk[81];
        + pb3::sizeof_ntrytes(81)
    // absorb oneof;
        + pb3::sizeof_oneof()
        + if !has_ntru_pk {
            // absorb null empty;
            0
        } else {
            // absorb tryte ntrupk[3072];
            pb3::sizeof_ntrytes(3072)
        }
    // commit;
        + 0
    // squeeze external tryte tag[78];
        + 0
    // mssig(tag);
        + pb3::mssig::sizeof_mssig(mss_sk)
}

/// Wrap `Announce` content.
///
/// # Arguments
///
/// * `mss_sk` -- channel owner's MSS private key.
///
/// * `opt_ntru_pk` -- channel owner's optional NTRU public key.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
pub fn wrap(mss_sk: &mss::PrivateKey, opt_ntru_pk: &Option<ntru::PublicKey>, s: &mut Spongos, b: &mut TritMutSlice) {
    pb3::wrap_absorb_trits(mss_sk.root(), s, b);
    if let Some(ntru_pk) = opt_ntru_pk {
        pb3::oneof(1).wrap_absorb(s, b);
        pb3::wrap_absorb_trits(ntru_pk.trits(), s, b);
    } else {
        pb3::oneof(0).wrap_absorb(s, b);
    }
    pb3::mssig::squeeze_wrap_mssig(mss_sk, s, b);
}

/// Unwrap `Announce` content.
///
/// # Arguments
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
/// # Return
///
/// MSS public key and optional NTRU public key or error code.
pub fn unwrap(s: &mut Spongos, b: &mut TritConstSlice) -> Result<(mss::PublicKey, Option<ntru::PublicKey>)> {
    let msspk = mss::PublicKey::unwrap_absorb_sized(s, b)?;
    let has_ntrupk = pb3::Tryte::unwrap_absorb_sized(s, b)?;
    let n = match has_ntrupk.0 {
        0 => None,
        1 => {
            let ntrupk = ntru::PublicKey::unwrap_absorb_sized(s, b)?;
            Some(ntrupk)
        },
        _ => return Err(Err::BadOneOf),
    };
    pb3::mssig::squeeze_unwrap_mssig_verify(&msspk, s, b)?;
    Ok((msspk, n))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::channel::msg;

    #[test]
    fn simple_with_ntrupk() {
        // secrets, nonces
        let prng_key_str = "PRNGKEY";
        let mss_nonce = Trits::from_str("MSSNONCE").unwrap();
        let ntru_nonce = Trits::from_str("NTRUNONCE").unwrap();

        // secret objects
        let prng = prng::dbg_init_str(prng_key_str);
        let d = 1;
        let mut mss_sk = mss::PrivateKey::gen(&prng, d, mss_nonce.slice());
        let mss_pk = mss_sk.public_key();
        let (_ntru_sk, ntru_pk) = ntru::gen(&prng, ntru_nonce.slice());

        // message
        let n = msg::announce::sizeof(&mss_sk, true);
        let mut buf = Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            msg::announce::wrap(&mss_sk, &Some(ntru_pk.clone()), &mut s, &mut b);
            assert_eq!(0, b.size());
            mss_sk.next();
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r = msg::announce::unwrap(&mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r == Ok((mss_pk, Some(ntru_pk))));
        }
    }

    #[test]
    fn simple_without_ntrupk() {
        // secrets, nonces
        let prng_key = Trits::from_str("PRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKE").unwrap();
        let mss_nonce = Trits::from_str("MSSNONCE").unwrap();

        // secret objects
        let prng = prng::PRNG::init(prng_key.slice());
        let d = 1;
        let mut mss_sk = mss::PrivateKey::gen(&prng, d, mss_nonce.slice());
        let mss_pk = mss_sk.public_key();

        // message
        let n = msg::announce::sizeof(&mss_sk, false);
        let mut buf = Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            msg::announce::wrap(&mss_sk, &None, &mut s, &mut b);
            assert_eq!(0, b.size());
            mss_sk.next();
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r = msg::announce::unwrap(&mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r == Ok((mss_pk, None)));
        }
    }

}
