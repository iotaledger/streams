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

use failure::Fallible;
use iota_mam_app::message::{self, HasLink};
use iota_mam_core::spongos;
use iota_mam_protobuf3::{command::*, io, types::*};

/// Type of `TaggedPacket` message content.
pub const TYPE: &str = "MAM9CHANNEL9TAGGEDPACKET";

pub struct ContentWrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Trytes,
    pub(crate) masked_payload: &'a Trytes,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<'a, Link, Store> message::ContentWrap<Store> for ContentWrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Fallible<&'c mut sizeof::Context> {
        let store = EmptyLinkStore::<<Link as HasLink>::Rel, ()>::default();
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(&store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        //TODO: Is bot public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<OS>,
    ) -> Fallible<&'c mut wrap::Context<OS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Trytes,
    pub(crate) masked_payload: Trytes,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<Link> ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Trytes::default(),
            masked_payload: Trytes::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Link, Store> message::ContentUnwrap<Store> for ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<IS>,
    ) -> Fallible<&'c mut unwrap::Context<IS>> {
        let mac = Mac(spongos::MAC_SIZE);
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}
