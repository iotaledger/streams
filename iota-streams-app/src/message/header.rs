//! `Header` prepended to each Streams message published in the Tangle.
//!
//! ```pb3
//! message Message {
//!     Header header;
//!     Content content;
//!     commit;
//! }
//! message Header {
//!     absorb byte version;
//!     absorb external byte appinst[81];
//!     absorb external byte msgid[27];
//!     absorb bytes type;
//! }
//! ```
//!
//! Fields:
//!
//! * `version` -- the Streams version; it describes the set of commands,
//! behaviour of commands, format of the `Header` message.
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
//! ```pb3
//! message Message {
//!     Header header;
//!     Content content;
//!     squeeze external byte msgid[27];
//!     commit;
//! }
//! message Header {
//!     absorb byte version;
//!     absorb external byte appinst[81];
//!     absorb bytes type;
//! }
//! ```
//!
//! In here `msgid` is squeezed and supposed to be random
//! hence solving the spam issue: spammed message will not
//! check. To be discussed.

use anyhow::{
    ensure,
    Result,
};

use iota_streams_core::{prelude::Vec, sponge::prp::PRP};
use iota_streams_protobuf3 as protobuf3;
use protobuf3::{
    command::*,
    io,
    types::*,
};

use super::*;

pub struct Header<Link> {
    pub version: Uint8,
    pub link: Link,
    pub multi_branching: u8,
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
            multi_branching: self.multi_branching.clone(),
            content_type: self.content_type.clone(),
        }
    }
}

impl<Link> Header<Link>
{
    pub fn new_with_type(link: Link, multi_branching: u8, content_type: &str) -> Self {
        Self {
            version: STREAMS_1_VER,
            link: link,
            multi_branching: multi_branching,
            content_type: Bytes(content_type.as_bytes().to_vec()),
        }
    }

    pub fn new(link: Link, multi_branching: u8) -> Self {
        Self {
            version: STREAMS_1_VER,
            link: link,
            multi_branching: multi_branching,
            content_type: Bytes(Vec::new()),
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
            .absorb(NBytes(vec![self.multi_branching]))?
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
            .absorb(&NBytes(vec![self.multi_branching]))?
            .absorb(&self.content_type)?
        ;
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
            .absorb(&mut NBytes(vec![self.multi_branching]))?
            .absorb(&mut self.content_type)?;
        ensure!(
            self.version == STREAMS_1_VER,
            "Message version not supported: {}.",
            self.version
        );
        Ok(ctx)
    }
}
