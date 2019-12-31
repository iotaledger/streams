//! `ChangeKey` message content. This message is published by channel author.
//! The message is linked to either `Announce` or `ChangeKey` message.
//!
//! ```pb3
//! message ChangeKey {
//!     join link msgid;
//!     absorb tryte msspk[81];
//!     commit;
//!     squeeze external tryte hash[78];
//!     mssig(hash) sig_with_msspk;
//!     mssig(hash) sig_with_linked_msspk;
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the message containing a trusted MSS public key.
//! This key is used to derive trust relationship to the `msspk` public key.
//!
//! * `msspk` -- a new MSS public key.
//!
//! * `hash` -- message hash value to be signed.
//!
//! * `sig_with_msspk` -- signature generated with the MSS private key corresponding
//! to the public key contained in `msspk` field -- proof of knowledge of private key.
//!
//! * `sig_with_linked_msspk` -- signature generated with the MSS private key
//! corresponding to the *trusted* public key contained in the linked message.
//!

use crate::app::channel::msg;
use crate::app::core::{AppInst, APPINST_SIZE, MsgId, MSGID_SIZE};
use crate::mss;
use crate::ntru;
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::prng::{self, PRNG};
use crate::psk::{self};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// Type of `ChangeKey` message content.
pub const TYPE: &'static str = "MAM9CHANNEL9CHANGEKEY";

/// Size of `ChangeKey` message content.
///
/// Arguments:
///
/// * `mss_sk` -- channel owner's MSS private key, corresponding to `msspk` public key.
///
/// * `linked_mss_sk` -- channel owner's MSS private key, corresponding to the MSS public key
/// linked by `msgid`.
pub fn sizeof(mss_sk: &mss::PrivateKey, linked_mss_sk: &mss::PrivateKey) -> usize {
    0
    // external join tryte mssig[27];
        + pb3::sizeof_ntrytes(27)
    // absorb tryte msspk[81];
        + pb3::sizeof_ntrytes(81)
    // commit;
        + 0
    // squeeze external tryte hash[78];
        + 0
    // mssig(hash) sig_with_msspk;
        + pb3::mssig::sizeof_mssig(mss_sk)
    // mssig(hash) sig_with_linked_msspk;
        + pb3::mssig::sizeof_mssig(linked_mss_sk)
}

/// Wrap `ChangeKey` message content.
///
/// Arguments:
///
/// * `msgid` -- link to the message with trusted public key.
///
/// * `slink` -- spongos instance of the message linked by `msgid`.
///
/// * `mss_sk` -- channel owner's MSS private key, corresponding to `msspk` public key.
///
/// * `linked_mss_sk` -- channel owner's MSS private key, corresponding to the MSS public key
/// linked by `msgid`.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
pub fn wrap(msgid: TritConstSlice, slink: &mut Spongos, mss_sk: &mss::PrivateKey, linked_mss_sk: &mss::PrivateKey, s: &mut Spongos, b: &mut TritMutSlice) {
    pb3::join::wrap_join(msgid, slink, s, b);
    //pb3::wrap_absorb_trits(mss_sk.root(), s, b);
    mss_sk.public_key().wrap_absorb(s, b);
    let hash = pb3::mssig::squeeze_mss_hash(s);
    pb3::mssig::wrap_mssig(hash.slice(), mss_sk, s, b);
    pb3::mssig::wrap_mssig(hash.slice(), linked_mss_sk, s, b);
}

/// Unwrap `ChangeKey` message content.
///
/// Arguments:
///
/// * `lookup_link` -- lookup function taking `msgid` as input and returning
/// spongos instance and MSS public key of the corresponding message.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
/// # Returns
///
/// * `mss_pk` -- verified and trusted MSS public key.
pub fn unwrap(lookup_link: impl Fn(TritConstSlice) -> Option<(Spongos, mss::PublicKey)>, s: &mut Spongos, b: &mut TritConstSlice) -> Result<mss::PublicKey> {
    let linked_mss_pk = pb3::join::unwrap_join(lookup_link, s, b)?;
    let mss_pk = mss::PublicKey::unwrap_absorb_sized(s, b)?;
    let hash = pb3::mssig::squeeze_mss_hash(s);
    pb3::mssig::unwrap_mssig_verify(hash.slice(), &mss_pk, s, b)?;
    pb3::mssig::unwrap_mssig_verify(hash.slice(), &linked_mss_pk, s, b)?;
    Ok(mss_pk)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wrap_unwrap() {
        // secrets, nonces
        let prng_key = trits::Trits::from_str("PRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKEPRNGKEYPRNGKEYPRNGKEYPRNGKE").unwrap();
        let mss_nonce = trits::Trits::from_str("MSSNONCE").unwrap();

        // secret objects
        let prng = prng::PRNG::init(prng_key.slice());
        let d_old = 2;
        let mut mss_sk_old = mss::PrivateKey::gen(&prng, d_old, mss_nonce.slice());
        let mss_pk_old = mss_sk_old.public_key();
        let d_new = 3;
        let mut mss_sk_new = mss::PrivateKey::gen(&prng, d_new, mss_nonce.slice());
        let mss_pk_new = mss_sk_new.public_key();
        let msgid = trits::Trits::cycle_str(81, "MSGID");

        // message

        let n = msg::change_key::sizeof(&mss_sk_old, &mss_sk_new);
        let mut buf = trits::Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            let mut slink = Spongos::init();
            msg::change_key::wrap(msgid.slice(), &mut slink, &mss_sk_new, &mss_sk_old, &mut s, &mut b);
            let _ = mss_sk_new.next();
            let _ = mss_sk_old.next();
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let slink = Spongos::init();
            let lookup_link =
                |m| if m == msgid.slice() {
                    Some((slink.clone(), mss_pk_old.clone()))
                } else {
                    None
                };
            let r = msg::change_key::unwrap(lookup_link, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r == Ok(mss_pk_new));
        }
    }
}
