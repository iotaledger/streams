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
use crypto::signatures::ed25519;

use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP,
    Result,
};
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{
        EmptyLinkStore,
        LinkStore,
    },
    types::*,
};

pub struct ContentWrap<'a, F, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) subscriber_private_key: &'a ed25519::SecretKey,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

#[async_trait(?Send)]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    Link::Rel: 'a + Eq + SkipFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, Link::Rel, ()>::default();
        ctx.join(&store, self.link)?
            .absorb(&self.subscriber_private_key.public_key())?
            .commit()?
            .ed25519(self.subscriber_private_key, HashSig)?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    Link::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, Link::Rel>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?
            .absorb(&self.subscriber_private_key.public_key())?
            .commit()?
            .ed25519(self.subscriber_private_key, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: Link::Rel,
    pub(crate) subscriber_public_key: ed25519::PublicKey,
    _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<F, Link: HasLink> Default for ContentUnwrap<F, Link> {
    fn default() -> Self {
        Self {
            link: Default::default(),
            subscriber_public_key: ed25519::PublicKey::try_from_bytes([0; 32]).unwrap(),
            _phantom: Default::default(),
        }
    }
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
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.subscriber_public_key)?
            .commit()?
            .ed25519(&self.subscriber_public_key, HashSig)?;
        Ok(ctx)
    }
}
