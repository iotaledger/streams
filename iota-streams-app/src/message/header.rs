//! `Header` prepended to each Streams message published in the Tangle.
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

use failure::{
    ensure,
    Fallible,
};
use std::str::FromStr;

use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            SpongosTbitWord,
            StringTbitWord,
        },
        Tbits,
    },
};
use iota_streams_protobuf3 as protobuf3;
use protobuf3::{
    command::*,
    io,
    types::*,
};

use super::*;

pub struct Header<TW, Link> {
    pub version: Trint3,
    pub link: Link,
    pub content_type: Trytes<TW>,
}

impl<TW, Link> Clone for Header<TW, Link>
where
    TW: Clone,
    Link: Clone,
{
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            link: self.link.clone(),
            content_type: self.content_type.clone(),
        }
    }
}

impl<TW, Link> Header<TW, Link>
where
    TW: StringTbitWord,
{
    pub fn new_with_type(link: Link, content_type: &str) -> Self {
        Self {
            version: STREAMS_1_VER,
            link: link,
            content_type: Trytes(Tbits::<TW>::from_str(content_type).unwrap()),
        }
    }

    pub fn new(link: Link) -> Self {
        Self {
            version: STREAMS_1_VER,
            link: link,
            content_type: Trytes(Tbits::zero(0)),
        }
    }
}

impl<TW, F, Link, Store> ContentWrap<TW, F, Store> for Header<TW, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Link: AbsorbExternalFallback<TW, F>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Fallible<&'c mut sizeof::Context<TW, F>> {
        ctx.absorb(&self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
        ctx.absorb(&self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&self.content_type)?;
        Ok(ctx)
    }
}

impl<TW, F, Link, Store> ContentUnwrap<TW, F, Store> for Header<TW, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Link: AbsorbExternalFallback<TW, F>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>> {
        ctx.absorb(&mut self.version)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&mut self.content_type)?;
        ensure!(
            self.version == STREAMS_1_VER,
            "Message version not supported: {}.",
            self.version
        );
        Ok(ctx)
    }
}
