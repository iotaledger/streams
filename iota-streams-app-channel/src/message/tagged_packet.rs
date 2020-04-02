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
use iota_streams_app::message::{self, HasLink};
use iota_streams_core::{
    sponge::{prp::PRP, spongos},
    tbits::{
        trinary,
        word::{BasicTbitWord, SpongosTbitWord},
    },
};
use iota_streams_protobuf3::{command::*, io, types::*};

/// Type of `TaggedPacket` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9TAGGEDPACKET";

pub struct ContentWrap<'a, TW, F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Trytes<TW>,
    pub(crate) masked_payload: &'a Trytes<TW>,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, TW, F, Link, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, F, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(
        &self,
        ctx: &'c mut sizeof::Context<TW, F>,
    ) -> Fallible<&'c mut sizeof::Context<TW, F>> {
        let store = EmptyLinkStore::<TW, F, <Link as HasLink>::Rel, ()>::default();
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(&store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        //TODO: Is bot public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<TW, F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Trytes<TW>,
    pub(crate) masked_payload: Trytes<TW>,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<TW, F, Link> ContentUnwrap<TW, F, Link>
where
    TW: BasicTbitWord,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Trytes::<TW>::default(),
            masked_payload: Trytes::<TW>::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F, Link, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<TW, F, Link>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}
