//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```pb3
//! message Unsubscribe {
//!     join link msgid;
//!     commit;
//!     squeeze tryte mac[27];
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Subscribe` message published by the subscriber.
//!
//! * `mac` -- authentication tag proving knowledge of the `unsubscribe_key` from the `Subscribe` message.

use crate::app::channel::msg;
use crate::ntru;
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// Type of `Unsubscribe` message content.
pub const TYPE: &'static str = "MAM9CHANNEL9UNSUBSCRIBE";

/// Size of `Unsubscribe` message content.
pub fn sizeof() -> usize {
    0
    // join link tryte tag[27];
        + pb3::join::sizeof_join()
    // commit;
        + 0
    // squeeze tryte mac[81];
        + pb3::sizeof_ntrytes(spongos::MAC_SIZE / 3)
}

/// Wrap `Unsubscribe` message content.
///
/// Arguments:
///
/// * `msgid` -- link to the message with trusted public key.
///
/// * `slink` -- spongos instance of the message linked by `msgid`.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
pub fn wrap(msgid: TritConstSlice, slink: &mut Spongos, s: &mut Spongos, b: &mut TritMutSlice) {
    pb3::join::wrap_join(msgid, slink, s, b);
    pb3::mac::wrap_mac(s, b);
}

/// Unwrap `Unsubscribe` message content.
///
/// Arguments:
///
/// * `lookup_link` -- lookup function taking `msgid` as input and returning
/// spongos instance and NTRU public key of the corresponding `Subscribe` message.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
pub fn unwrap(lookup_link: impl Fn(TritConstSlice) -> Option<(Spongos, ntru::PublicKey)>, s: &mut Spongos, b: &mut TritConstSlice) -> Result<ntru::PublicKey> {
    let sub_pk = pb3::join::unwrap_join(lookup_link, s, b)?;
    pb3::mac::unwrap_mac(s, b)?;
    Ok(sub_pk)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prng;

    #[test]
    fn wrap_unwrap() {
        // secrets, nonces
        let sub_ntru_nonce = Trits::from_str("SUBNTRUNONCE").unwrap();

        // secret objects
        let prng = prng::dbg_init_str("PRNGKEY");
        let (sub_ntru_sk, sub_ntru_pk) = ntru::gen(&prng, sub_ntru_nonce.slice());
        let msgid = trits::Trits::cycle_str(81, "MSGID");

        // message
        let n = msg::unsubscribe::sizeof();
        let mut buf = trits::Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut slink = Spongos::init();
            let mut b = buf.mut_slice();
            msg::unsubscribe::wrap(msgid.slice(), &mut slink, &mut s, &mut b);
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let slink = Spongos::init();
            let mut b = buf.slice();
            let lookup_link =
                |m| if m == msgid.slice() {
                    Some((slink.clone(), sub_ntru_pk.clone()))
                } else {
                    None
                };
            let r = msg::unsubscribe::unwrap(lookup_link, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(dbg!(r) == Ok(sub_ntru_pk));
        }
    }
}
