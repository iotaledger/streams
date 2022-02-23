//! `Subscribe` message content. This message is published by a user willing to become
//! a subscriber to this channel.
//!
//! It contains subscriber's Ed25519 public key that will be used
//! in keyload to encrypt session keys. Subscriber's Ed25519 public key is encrypted with
//! the `unsubscribe_key` which in turn is encapsulated for channel owner using
//! owner's Ed25519 public key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's Ed25519 public key in order to maintain privacy.
//!
//! Channel Owner must maintain the resulting spongos state associated to the Subscriber's
//! Ed25519 public key.
//!
//! ```ddml
//! message Subscribe {
//!     join link msgid;
//!     x25519(key) byte unsubscribe_key[32];
//!     commit;
//!     mask byte pk[32];
//!     commit;
//!     squeeze external byte hash[78];
//!     mssig(hash) sig;
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Announce` message containing channel owner's trusted Ed25519 public key.
//! This key is used to protect subscriber's identity by encrypting subscriber's Ed25519 public key.
//!
//! * `unsubscribe_key` -- encapsulated secret key that serves as encryption key and as password to unsubscribe from the
//!   channel.
//!
//! * `pk` -- subscriber's Ed25519 public key.
//!
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with the senders private key.
//!
//! Note, the `unsubscribe_key` is masked and verified in the `x25519` operation and
//! thus is not additionally `absorb`ed in this message.
use core::convert::TryInto;

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
    pub unsubscribe_key: NBytes<U32>,
    pub(crate) subscriber_private_key: &'a ed25519::SecretKey,
    pub(crate) author_public_key: &'a ed25519::PublicKey,
    pub(crate) _phantom: core::marker::PhantomData<(Link, F)>,
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
        ctx.join(&store, self.link)?
            .x25519(&self.author_public_key.try_into()?, &self.unsubscribe_key)?
            .mask(&self.subscriber_private_key.public_key())?
            .ed25519(self.subscriber_private_key, HashSig)?;
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
        ctx.join(store, self.link)?
            .x25519(&self.author_public_key.try_into()?, &self.unsubscribe_key)?
            .mask(&self.subscriber_private_key.public_key())?
            .ed25519(self.subscriber_private_key, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, F, Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    pub unsubscribe_key: NBytes<U32>,
    pub subscriber_public_key: ed25519::PublicKey,
    author_private_key: &'a ed25519::SecretKey,
    _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link> ContentUnwrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(author_private_key: &'a ed25519::SecretKey) -> Self {
        Self {
            link: Default::default(),
            unsubscribe_key: Default::default(),
            subscriber_public_key: ed25519::PublicKey::try_from_bytes([0; 32]).unwrap(),
            author_private_key,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<'a, F, Link>
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
            .x25519(&self.author_private_key.try_into()?, &mut self.unsubscribe_key)?
            .mask(&mut self.subscriber_public_key)?
            .ed25519(&self.subscriber_public_key, HashSig)?;
        Ok(ctx)
    }
}
