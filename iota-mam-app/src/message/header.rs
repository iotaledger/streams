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

use failure::{ensure, Fallible};
use std::str::FromStr;

use iota_mam_core::trits::Trits;
use iota_mam_protobuf3 as protobuf3;
use protobuf3::{command::*, io, types::*};

use super::*;

#[derive(Clone, Debug, Default)]
pub struct Header<Link> {
    pub version: Trint3,
    pub link: Link,
    pub content_type: Trytes,
}

impl<Link> Header<Link> {
    pub fn new_with_type(link: Link, content_type: &str) -> Self {
        Self {
            version: MAM_1_1_VER,
            link: link,
            content_type: Trytes(Trits::from_str(content_type).unwrap()),
        }
    }

    pub fn new(link: Link) -> Self {
        Self {
            version: MAM_1_1_VER,
            link: link,
            content_type: Trytes(Trits::zero(0)),
        }
    }
}

impl<Link, Store> ContentWrap<Store> for Header<Link>
where
    Link: AbsorbExternalFallback,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Fallible<&'c mut sizeof::Context> {
        ctx.absorb(&self.version)?
            .absorb(External(&self.link))?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<OS>,
    ) -> Fallible<&'c mut wrap::Context<OS>> {
        ctx.absorb(&self.version)?
            .absorb(External(&self.link))?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }
}

impl<Link, Store> ContentUnwrap<Store> for Header<Link>
where
    Link: AbsorbExternalFallback,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<IS>,
    ) -> Fallible<&'c mut unwrap::Context<IS>> {
        ctx.absorb(&mut self.version)?
            .absorb(External(&self.link))?
            .absorb(&mut self.content_type)?;
        ensure!(
            self.version == MAM_1_1_VER,
            "Message version not supported: {}.",
            self.version
        );
        Ok(ctx)
    }
}
