//! `Header` prepended to each MAM message published in the Tangle.
//!
//! ```pb3
//! message Message {
//!     Header header;
//!     Content content;
//!     commit;
//! }
//! message Header {
//!     absorb tryte version;
//!     absorb external tryte appinst[81];
//!     absorb external tryte msgid[27];
//!     absorb trytes type;
//! }
//! ```
//!
//! Fields:
//!
//! * `version` -- the MAM version; it describes the set of commands,
//! behaviour of commands, format of the `Header` message.
//!
//! * `type` -- a string desribing the type of the content following
//! this `Header` message.
//!
//! * `appinst` -- MAM application instance identifier, externally stored
//! in `address` field of Transaction.
//!
//! * `msgid` -- MAM application message identifier, externally stored
//! in `tag` field of Transaction.
//!
//! # Alternative design
//!
//! ```pb3
//! message Message {
//!     Header header;
//!     Content content;
//!     squeeze external tryte msgid[27];
//!     commit;
//! }
//! message Header {
//!     absorb tryte version;
//!     absorb external tryte appinst[81];
//!     absorb trytes type;
//! }
//! ```
//!
//! In here `msgid` is squeezed and supposed to be random
//! hence solving the spam issue: spammed message will not
//! check. To be discussed.

use crate::app::core::{APPINST_SIZE, AppInst, MSGID_SIZE, MsgId};
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// MAM1 version number.
pub const MAM_1_VER: usize = 0;

/// MAM1.1 version number.
pub const MAM_1_1_VER: usize = 1;

/// Size of encoded `Header` message.
///
/// Arguments:
///
/// * `type_size` -- size of `type` string in trytes.
pub fn sizeof(type_size: usize) -> usize {
    0
    // absorb tryte version;
        + pb3::sizeof_tryte()
    // absorb trytes type;
        + pb3::sizeof_trytes(type_size)
    // absorb external tryte appinst[81];
        + 0
    // absorb external tryte msgid[27];
        + 0
}

pub fn wrap(typ: &pb3::Trytes, appinst: &AppInst, msgid: &MsgId, s: &mut Spongos, b: &mut TritMutSlice) {
    assert_eq!(APPINST_SIZE, appinst.id.size());
    assert_eq!(MSGID_SIZE, msgid.id.size());
    let version = pb3::tryte(MAM_1_1_VER as trits::Trint3);
    version.wrap_absorb(s, b);
    typ.wrap_absorb(s, b);
    s.absorb(appinst.id.slice());
    s.absorb(msgid.id.slice());
}

pub fn unwrap(appinst: &AppInst, msgid: &MsgId, s: &mut Spongos, b: &mut TritConstSlice) -> Result<pb3::Trytes> {
    assert_eq!(APPINST_SIZE, appinst.id.size());
    assert_eq!(MSGID_SIZE, msgid.id.size());
    let version = pb3::Tryte::unwrap_absorb_sized(s, b)?;
    guard(pb3::tryte(MAM_1_1_VER as trits::Trint3) == version, Err::VersionUnsupported)?;
    let typ = pb3::Trytes::unwrap_absorb_sized(s, b)?;
    s.absorb(appinst.id.slice());
    s.absorb(msgid.id.slice());
    Ok(typ)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::core::msg;

    #[test]
    fn simple() {
        let typ_str = "TESTMESSAGE";
        let appinst_str = "APPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPP";
        let msgid_str = "MSGMSGMSGMSGMSGMSGMSGMSGMSG";

        // message
        let n = msg::header::sizeof(typ_str.len());
        let mut buf = trits::Trits::zero(n);
        let typ = pb3::Trytes(Trits::from_str(typ_str).unwrap());
        let appinst = AppInst{ id: Trits::from_str(appinst_str).unwrap() };
        let msgid = MsgId{ id: Trits::from_str(msgid_str).unwrap() };

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            msg::header::wrap(&typ, &appinst, &msgid, &mut s, &mut b);
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r = msg::header::unwrap(&appinst, &msgid, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r == Ok(typ));
        }
    }
}
