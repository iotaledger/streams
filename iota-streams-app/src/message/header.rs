//! `Header` prepended to each Streams message published in the Tangle.
//!
//! ```ddml
//! message Message {
//!     Header header;
//!     Content content;
//!     commit;
//! }
//! message Header {
//!     absorb u8 version;
//!     absorb external u8 appinst[32];
//!     absorb external u8 msgid[16];
//!     absorb u8 flags;
//!     absorb uint len;
//!     absorb u8 type[len];
//! }
//! ```
//!
//! Fields:
//!
//! * `version` -- the Streams version; it describes the set of commands,
//! behaviour of commands, format of the `Header` message.
//!
//! * `flags` -- a byte desribing app-specific flags.
//!
//! * `type` -- a string desribing the type of the content following
//! this `Header` message.
//!
//! * `appinst` -- Streams application instance identifier, externally stored
//! in `address` field of Transaction.
//!
//! * `msgid` -- Streams application message identifier, externally stored
//! in `tag` field of Transaction.
//!
//! # Alternative design
//!
//! ```ddml
//! message Message {
//!     Header header;
//!     Content content;
//!     squeeze external u8 msgid[16];
//!     commit;
//! }
//! message Header {
//!     absorb byte version;
//!     absorb external u8 appinst[32];
//!     absorb uint len;
//!     absorb u8 type[len];
//! }
//! ```
//!
//! In here `msgid` is squeezed and supposed to be random
//! hence solving the spam issue: spammed message will not
//! check. To be discussed.

use anyhow::{
    bail,
    ensure,
    Result,
};

use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_ddml as ddml;
use ddml::{
    command::*,
    io,
    types::*,
};

use super::*;

pub const FLAG_BRANCHING_MASK: u8 = 1;

pub struct Header<Link> {
    pub version: Uint8,
    pub link: Link,
    pub flags: Uint8,
    pub content_type: Bytes,
}

impl<Link> Clone for Header<Link>
where
    Link: Clone,
{
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            link: self.link.clone(),
            flags: self.flags,
            content_type: self.content_type.clone(),
        }
    }
}

impl<Link> Header<Link> {
    pub fn new_with_type(link: Link, flags: u8, content_type: &str) -> Self {
        Self {
            version: STREAMS_1_VER,
            link: link,
            flags: Uint8(flags),
            content_type: Bytes(content_type.as_bytes().to_vec()),
        }
    }

    pub fn new(link: Link, flags: u8) -> Self {
        Self {
            version: STREAMS_1_VER,
            link,
            flags: Uint8(flags),
            content_type: Bytes(Vec::new()),
        }
    }

    pub fn content_type_str(&self) -> Result<&str> {
        match core::str::from_utf8(&self.content_type.0[..]) {
            Ok(s) => Ok(s),
            Err(err) => bail!("Bad content type str: {}", err),
        }
    }
}

impl<F, Link, Store> ContentWrap<F, Store> for Header<Link>
where
    F: PRP,
    Link: AbsorbExternalFallback<F>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(self.flags)?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.absorb(&self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(self.flags)?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }
}

impl<F, Link, Store> ContentUnwrap<F, Store> for Header<Link>
where
    F: PRP,
    Link: AbsorbExternalFallback<F>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.absorb(&mut self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&mut self.flags)?
            .absorb(&mut self.content_type)?;
        ensure!(
            self.version == STREAMS_1_VER,
            "Message version not supported: {}.",
            self.version
        );
        Ok(ctx)
    }
}
