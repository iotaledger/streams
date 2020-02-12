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

use std::str::FromStr;
use failure::ensure;

use iota_mam_core::trits::{Trits};
use iota_mam_protobuf3 as protobuf3;
use protobuf3::{command::*, io, Result, sizeof, types::*, unwrap, wrap};

use super::{ContentWrap, ContentUnwrap, version::*};

#[derive(Clone, Debug, Default)]
pub struct Header<Link> {
    pub(crate) version: Trint3,
    pub(crate) link: Link,
    pub(crate) content_type: Trytes,
}

impl<Link> Header<Link> {
    pub fn new(link: Link, content_type: &str) -> Self {
        Self {
            version: MAM_1_1_VER,
            link: link,
            content_type: protobuf3::Trytes(Trits::from_str(content_type).unwrap()),
        }
    }
}

impl<Link> Header<Link> where Link: AbsorbExternalFallback {
    pub fn sizeof<'a>(&self, ctx: &'a mut sizeof::Context) -> Result<&'a mut sizeof::Context> {
        ctx
            .absorb(&self.version)?
            .absorb(External(&self.link))?
            .absorb(&self.content_type)?
            ;
        Ok(ctx)
    }

    pub fn wrap<'a, OS: io::OStream>(&'a self, ctx: &'a mut wrap::Context<OS>) -> Result<&'a mut wrap::Context<OS>> {
        ctx
            .absorb(&self.version)?
            .absorb(External(&self.link))?
            .absorb(&self.content_type)?
            ;
        Ok(ctx)
    }

    pub fn unwrap<'a, IS: io::IStream>(&'a mut self, ctx: &'a mut unwrap::Context<IS>) -> Result<&'a mut unwrap::Context<IS>> {
        ctx
            .absorb(&mut self.version)?
            .absorb(External(&self.link))?
            .absorb(&mut self.content_type)?
            ;
        ensure!(self.version == MAM_1_1_VER);
        Ok(ctx)
    }
}

impl<Link> ContentWrap for Header<Link> where Link: AbsorbExternalFallback {
    fn sizeof2<'a>(&self, ctx: &'a mut sizeof::Context) -> Result<&'a mut sizeof::Context> {
        self.sizeof(ctx)
    }

    fn wrap2<'a, OS: io::OStream>(&'a self, ctx: &'a mut wrap::Context<OS>) -> Result<&'a mut wrap::Context<OS>> {
        self.wrap(ctx)
    }
}

impl<Link> ContentUnwrap for Header<Link> where Link: AbsorbExternalFallback {
    fn unwrap2<'a, IS: io::IStream>(&'a mut self, ctx: &'a mut unwrap::Context<IS>) -> Result<&'a mut unwrap::Context<IS>> {
        self.unwrap(ctx)
    }
}

/*
pub fn wrap<'a, OS: io::OStream, Link>(ctx: &'a mut wrap::Context<OS>, hdr: &'a Header<Link>) -> Result<&'a mut wrap::Context<OS>> where
    //wrap::Context<OS>: Absorb<&'a protobuf3::Trint3>
//+ Absorb<&'a Link>
    //+ Absorb<&'a protobuf3::Trytes>
{
    ctx
        .absorb(&self.version)?
    //.absorb(&self.link)?
    .absorb(&self.content_type)?
    ;
    Ok(ctx)
}
 */

/*
/// Size of encoded `Header` message.
///
/// Arguments:
///
/// * `type_size` -- size of `type` string in trytes.
pub fn sizeof(type_size: usize) -> usize {
    0
    // absorb tryte version;
        + protobuf3::sizeof_tryte()
    // absorb trytes type;
        + protobuf3::sizeof_trytes(type_size)
    // absorb external tryte appinst[81];
        + 0
    // absorb external tryte msgid[27];
        + 0
}

pub fn wrap(
    typ: &protobuf3::Trytes,
    appinst: &AppInst,
    msgid: &MsgId,
    s: &mut Spongos,
    b: &mut TritSliceMut,
) {
    assert_eq!(APPINST_SIZE, appinst.id.size());
    assert_eq!(MSGID_SIZE, msgid.id.size());
    let version = protobuf3::tryte(Trint3(MAM_1_1_VER as i8));
    version.wrap_absorb(s, b);
    typ.wrap_absorb(s, b);
    s.absorb(appinst.id.slice());
    s.absorb(msgid.id.slice());
}

pub fn unwrap(
    appinst: &AppInst,
    msgid: &MsgId,
    s: &mut Spongos,
    b: &mut TritSlice,
) -> Result<protobuf3::Trytes> {
    assert_eq!(APPINST_SIZE, appinst.id.size());
    assert_eq!(MSGID_SIZE, msgid.id.size());
    let version = Trint3::unwrap_absorb_sized(s, b)?;
    guard(
        protobuf3::tryte(Trint3(MAM_1_1_VER as i8)) == version,
        Err::VersionUnsupported,
    )?;
    let typ = protobuf3::Trytes::unwrap_absorb_sized(s, b)?;
    s.absorb(appinst.id.slice());
    s.absorb(msgid.id.slice());
    Ok(typ)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::msg;
    use iota_mam_core::trits::Trits;

    #[test]
    fn simple() {
        let typ_str = "TESTMESSAGE";
        let appinst_str =
            "APPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPPAPP";
        let msgid_str = "MSGMSGMSGMSGMSGMSGMSGMSGMSG";

        // message
        let n = msg::header::sizeof(typ_str.len());
        let mut buf = Trits::zero(n);
        let typ = protobuf3::Trytes(Trits::from_str(typ_str).unwrap());
        let appinst = AppInst {
            id: Trits::from_str(appinst_str).unwrap(),
        };
        let msgid = MsgId {
            id: Trits::from_str(msgid_str).unwrap(),
        };

        // wrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice_mut();
            msg::header::wrap(&typ, &appinst, &msgid, &mut s, &mut b);
            assert_eq!(0, b.size());
        }

        // unwrap
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r = msg::header::unwrap(&appinst, &msgid, &mut s, &mut b);
            assert_eq!(0, b.size());
            assert!(r.is_ok() && r.unwrap() == typ);
        }
    }
}
 */

#[cfg(test)]
mod test {
    #[test]
    fn simple() {
        let typ_str = "TESTMESSAGE";
    }
}
