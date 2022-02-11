//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```ddml
//! message Unsubscribe {
//!     join link msgid;
//!     absorb u8 ed25519pk[32];
//!     commit;
//!     squeeze external byte hash[32];
//!     mssig(hash) sig;
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Subscribe` message published by the subscriber.
//!
//! * `ed25519pk` -- subscriber's Ed25519 public key.
//!
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with the senders private key.

use core::marker::PhantomData;

use iota_streams_app::{
    id::UserIdentity,
    message::{self, ContentSign, ContentVerify, HasLink},
};
use iota_streams_core::{async_trait, prelude::Box, sponge::prp::PRP, Result};
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{EmptyLinkStore, LinkStore},
    types::*,
};

pub struct ContentWrap<'a, F, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) subscriber_id: &'a UserIdentity<F>,
    pub(crate) _phantom: PhantomData<(F, Link)>,
}

#[async_trait(?Send)]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?;
        self.subscriber_id.id.sizeof(ctx).await?.commit()?;
        let ctx = self.subscriber_id.sizeof(ctx).await?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?;
        self.subscriber_id.id.wrap(store, ctx).await?.commit()?;
        let ctx = self.subscriber_id.sign(ctx).await?;
        Ok(ctx)
    }
}

#[derive(Default)]
pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) subscriber_id: UserIdentity<F>,
    _phantom: PhantomData<(F, Link)>,
}

#[async_trait(?Send)]
impl<F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.join(store, &mut self.link)?;
        self.subscriber_id.id.unwrap(store, ctx).await?.commit()?;
        self.subscriber_id.verify(ctx).await?;
        Ok(ctx)
    }
}
