//! `Subscribe` message content. This message is published by a user willing to become
//! a subscriber to this channel. It contains subscriber's NTRU public key that will be used
//! in keyload to encrypt session keys. Subscriber's NTRU public key is encrypted with
//! the `unsubscribe_key` which in turn is encapsulated for channel owner using
//! owner's NTRU public key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's NTRU public key in order to maintain privacy.
//!
//! Channel Owner must maintain the resulting spongos state associated to the Subscriber's
//! NTRU public key.
//!
//! Note, in the `Channel` Application Subscriber doesn't have signature keys and thus
//! can't prove possesion of the NTRU private key with signature. Such proof can
//! be established in an interactive protocol by channel Owner's request.
//! Such protocol is out of scope. To be discussed.
//!
//! ```pb3
//! message Subscribe {
//!     join link msgid;
//!     ntrukem(key) tryte unsubscribe_key[3072];
//!     commit;
//!     mask tryte ntrupk[3072];
//!     commit;
//!     squeeze tryte mac[27];
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Announce` message containing channel owner's trusted NTRU public key.
//! This key is used to protect subscriber's identity by encrypting subscriber's NTRU public key.
//!
//! * `unsubscribe_key` -- encapsulated secret key that serves as encryption key and as password to unsubscribe from the channel.
//!
//! * `ntrupk` -- subscriber's NTRU public key.
//!
//! * `mac` -- authentication tag.
//!
//! Note, the `unsubscribe_key` is masked and verified in the `ntrukem` operation and
//! thus is not additionally `absorb`ed in this message.

use crate::ntru;
use crate::pb3::{self, Mask, Result};
use crate::prng::PRNG;
use crate::spongos::{self, Spongos};
use crate::trits::{TritSlice, TritSliceMut, Trits};

/// Type of `Subscribe` message content.
pub const TYPE: &str = "MAM9CHANNEL9SUBSCRIBE";

/// Size of `Subscribe` message content.
pub fn sizeof() -> usize {
    0
    // join link tryte tag[27];
        + pb3::join::sizeof_join()
    // ntrukem(key) tryte unsubscribe_key;
        + pb3::ntrukem::sizeof_ntrukem()
    // commit;
        + 0
    // mask tryte ntrupk[3072];
        + pb3::sizeof_ntrytes(ntru::PK_SIZE / 3)
    // commit;
        + 0
    // squeeze tryte mac[81];
        + pb3::sizeof_ntrytes(spongos::MAC_SIZE / 3)
}

/// Wrap `Subscribe` message content.
///
/// Arguments:
///
/// * `msgid` -- link to the message with trusted public key.
///
/// * `slink` -- spongos instance of the message linked by `msgid`.
///
/// * `prng` -- PRNG used to generate the `unsubscribe_key` and for `ntrukem` operation.
///
/// * `nonce` -- nonce to be used with `prng`.
///
/// * `sub_pk` -- subscriber's NTRU public key.
///
/// * `ch_pk` -- channel owner's NTRU public key.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
pub fn wrap(
    msgid: TritSlice,
    slink: &mut Spongos,
    prng: &PRNG,
    nonce: TritSlice,
    sub_pk: &ntru::PublicKey,
    ch_pk: &ntru::PublicKey,
    s: &mut Spongos,
    b: &mut TritSliceMut,
) {
    pb3::join::wrap_join(msgid, slink, s, b);
    //TODO: fix `nonce`, use `sub_pk`, `ch_pk`.
    let mut unsubscribe_key = Trits::zero(spongos::KEY_SIZE);
    prng.gen(nonce, unsubscribe_key.slice_mut());
    pb3::ntrukem::wrap_ntrukem(unsubscribe_key.slice(), ch_pk, prng, nonce, s, b);
    s.commit();
    sub_pk.wrap_mask(s, b);
    pb3::mac::wrap_mac(s, b);
}

/// Unwrap `Subscribe` message content.
///
/// Arguments:
///
/// * `lookup_link` -- lookup function taking `msgid` as input and returning
/// spongos instance and MSS public key of the corresponding message.
///
/// * `ch_sk` -- channel owner's NTRU private key.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
pub fn unwrap(
    lookup_link: impl Fn(TritSlice) -> Option<(Spongos, ())>,
    ch_sk: &ntru::PrivateKey,
    s: &mut Spongos,
    b: &mut TritSlice,
) -> Result<ntru::PublicKey> {
    pb3::join::unwrap_join(lookup_link, s, b)?;
    let mut unsubscribe_key = Trits::zero(spongos::KEY_SIZE);
    pb3::ntrukem::unwrap_ntrukem(unsubscribe_key.slice_mut(), ch_sk, s, b)?;
    s.commit();
    let sub_pk = ntru::PublicKey::unwrap_mask_sized(s, b)?;
    pb3::mac::unwrap_mac(s, b)?;
    Ok(sub_pk)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::channel::msg;
    use crate::prng;
    use crate::trits::Trits;

    #[test]
    fn wrap_unwrap() {
        // secrets, nonces
        let sub_ntru_nonce = Trits::from_str("SUBNTRUNONCE").unwrap();
        let ch_ntru_nonce = Trits::from_str("CHNTRUNONCE").unwrap();
        let unsubscribe_nonce = Trits::from_str("UNSUBSCRIBE").unwrap();

        // secret objects
        let prng = prng::dbg_init_str("PRNGKEY");
        let (_sub_ntru_sk, sub_ntru_pk) = ntru::gen(&prng, sub_ntru_nonce.slice());
        let (ch_ntru_sk, ch_ntru_pk) = ntru::gen(&prng, ch_ntru_nonce.slice());
        let msgid = Trits::cycle_str(81, "MSGID");

        // message
        let n = msg::subscribe::sizeof();
        let mut buf = Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut slink = Spongos::init();
            let mut b = buf.slice_mut();
            msg::subscribe::wrap(
                msgid.slice(),
                &mut slink,
                &prng,
                unsubscribe_nonce.slice(),
                &sub_ntru_pk,
                &ch_ntru_pk,
                &mut s,
                &mut b,
            );
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let slink = Spongos::init();
            let mut b = buf.slice();
            let lookup_link = |m: TritSlice| {
                if m == msgid.slice() {
                    Some((slink.clone(), ()))
                } else {
                    None
                }
            };
            let r = msg::subscribe::unwrap(lookup_link, &ch_ntru_sk, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(dbg!(r) == Ok(sub_ntru_pk));
        }
    }
}
