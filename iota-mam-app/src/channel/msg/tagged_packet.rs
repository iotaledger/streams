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

use failure::bail;

use iota_mam_core::spongos;
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};
use crate::Result;
use crate::core::HasLink;

/// Type of `TaggedPacket` message content.
pub const TYPE: &str = "MAM9CHANNEL9TAGGEDPACKET";

pub struct ContentWrap<'a, RelLink: 'a, Store: 'a> {
    pub(crate) store: &'a Store,
    pub(crate) link: &'a RelLink,
    pub(crate) public_payload: &'a Trytes,
    pub(crate) masked_payload: &'a Trytes,
}

impl<'a, RelLink: 'a, Store: 'a> ContentWrap<'a, RelLink, Store> where
    RelLink: Eq + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub(crate) fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx
            .join(self.store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?
        ;
        //TODO: Is bot public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }
    pub(crate) fn wrap<'c, OS: io::OStream>(&self, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx
            .join(self.store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?
        ;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, RelLink, Store> {
    pub(crate) store: &'a Store,
    pub(crate) link: RelLink,
    pub(crate) public_payload: Trytes,
    pub(crate) masked_payload: Trytes,
}

impl<'a, RelLink: 'a, Store: 'a> ContentUnwrap<'a, RelLink, Store> where
    RelLink: Eq + Default + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub fn new(store: &'a Store) -> Self {
        Self {
            store: store,
            link: RelLink::default(),
            public_payload: Trytes::default(),
            masked_payload: Trytes::default(),
        }
    }

    pub(crate) fn unwrap<'c, IS: io::IStream>(&mut self, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx
            .join(self.store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .commit()?
            .squeeze(&mac)?
        ;
        Ok(ctx)
    }
}
