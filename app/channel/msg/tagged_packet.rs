//! `TaggedPacket` message content. The message may be linked to any other message
//! in the channel. It contains both plain and masked payloads. The message is
//! authenticated with MAC and can be published by channel owner or by a recipient.
//!
//! ```pb3
//! message TaggedPacket {
//!     join link msgid;
//!     absorb trytes public_payload;
//!     mask trytes masked_payload;
//!     commit;
//!     squeeze tryte mac[81];
//! }
//! ```
//!
//! # Fields
//!
//! * `msgid` -- link to the base message.
//!
//! * `public_payload` -- public part of payload.
//!
//! * `masked_payload` -- masked part of payload.
//!
//! * `mac` -- MAC of the message.
//!

use crate::app::channel::msg;
use crate::app::core::{MSGID_SIZE, MsgId};
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// Type of `TaggedPacket` message content.
pub const TYPE: &'static str = "MAM9TAGGEDPACKET";

/// Size of `SignedPacket` message content.
///
/// # Arguments
///
/// * `public_trytes` -- size of public payload in trytes.
///
/// * `masked_trytes` -- size of masked payload in trytes.
pub fn sizeof(public_trytes: usize, masked_trytes: usize) -> usize
{
    0
    // join link msgid;
        + pb3::sizeof_ntrytes(MSGID_SIZE / 3)
    // absorb trytes public_payload;
        + pb3::sizeof_trytes(public_trytes)
    // mask trytes masked_payload;
        + pb3::sizeof_trytes(masked_trytes)
    // mac;
        + pb3::mac::sizeof_mac()
}

/// Wrap `TaggedPacket` content.
///
/// # Arguments
///
/// * `msgid` -- link to the base message.
///
/// * `slink` -- spongos instance of the message linked by `msgid`.
///
/// * `public_payload` -- public payload.
///
/// * `masked_payload` -- masked payload.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
pub fn wrap(msgid: &MsgId, slink: &mut Spongos, public_payload: &pb3::Trytes, masked_payload: &pb3::Trytes, s: &mut Spongos, b: &mut TritMutSlice) {
    assert!(public_payload.size() % 3 == 0);
    assert!(masked_payload.size() % 3 == 0);
    pb3::join::wrap_join(msgid.id.slice(), slink, s, b);
    public_payload.wrap_absorb(s, b);
    masked_payload.wrap_mask(s, b);
    pb3::mac::wrap_mac(s, b);
}

/// Unwrap `TaggedPacket` content.
///
/// # Arguments
///
/// * `lookup_link` -- lookup function taking `msgid` as input and returning
/// spongos instance.
///
/// * `s` -- current spongos instance.
///
/// * `b` -- output buffer.
///
/// # Return
///
/// A pair of public and masked payloads or error code.
pub fn unwrap(lookup_link: impl Fn(TritConstSlice) -> Option<(Spongos, ())>, s: &mut Spongos, b: &mut TritConstSlice) -> Result<(pb3::Trytes, pb3::Trytes)> {
    pb3::join::unwrap_join(lookup_link, s, b)?;
    let public_payload = pb3::Trytes::unwrap_absorb_sized(s, b)?;
    let masked_payload = pb3::Trytes::unwrap_mask_sized(s, b)?;
    pb3::mac::unwrap_mac(s, b)?;
    Ok((public_payload, masked_payload))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prng;

    #[test]
    fn wrap_unwrap() {
        // data objects
        let msgid = MsgId{id: Trits::cycle_str(81, "MSGID"),};
        let public_payload = pb3::Trytes(Trits::cycle_str(555, "PUBLIC9PAYLOAD"));
        let masked_payload = pb3::Trytes(Trits::cycle_str(444, "MASKED9PAYLOAD"));

        // message
        let n = msg::tagged_packet::sizeof(public_payload.size() / 3, masked_payload.size() / 3);
        let mut buf = Trits::zero(n);

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            let mut slink = Spongos::init();
            msg::tagged_packet::wrap(&msgid, &mut slink, &public_payload, &masked_payload, &mut s, &mut b);
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let mut slink = Spongos::init();
            let r = msg::tagged_packet::unwrap(|m| if m == msgid.id.slice() { Some((slink.clone(), ())) } else { None }, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r == Ok((public_payload, masked_payload)));
        }
    }
}
