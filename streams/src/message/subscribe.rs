//! `Subscribe` message _wrapping_ and _unwrapping_. 
//! 
//! `Subscribe` messages are published by a user willing to become a subscriber to this channel.
//!
//! They contain the subscriber's identifier that will be used in keyload
//! messages to encrypt session keys.
//! 
//! Subscriber's Ed25519 public key is encrypted with the `unsubscribe_key`
//! which in turn is encapsulated for channel owner using owner's Ed25519 public
//! key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's Ed25519 public key in order to
//! maintain privacy.
//!
//! Channel Owner must maintain the resulting spongos state associated to the Subscriber's
//! Ed25519 public key.
//!
//! ```ddml
//! message Subscribe {
//!     skip                    link    msgid;
//!     join(msgid);
//!     x25519(pub/priv_key)    u8      x25519_auth_pubkey[32];
//!     commit;
//!     mask                    u8      unsubscribe_key[32]; 
//!     mask                    u8      pk[32];
//!     commit;
//!     squeeze external        u8      hash[64];
//!     ed25519(hash)           u8      signature[64];
//! }
//! ```
use core::marker::PhantomData;
use core::convert::TryInto;

use crypto::signatures::ed25519;

use lets::message::{
    self,
    HasLink,
};
use spongos::sponge::prp::PRP;
// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     sponge::prp::PRP,
//     Result,
// };
// use iota_streams_ddml::{
//     command::*,
//     io,
//     link_store::{
//         EmptyLinkStore,
//         LinkStore,
//     },
//     types::*,
// };

pub struct ContentWrap<'a, F, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub unsubscribe_key: NBytes<U32>,
    pub(crate) subscriber_private_key: &'a ed25519::SecretKey,
    pub(crate) author_public_key: &'a ed25519::PublicKey,
    pub(crate) _phantom: PhantomData<(Link, F)>,
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
    _phantom: PhantomData<(F, Link)>,
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
            _phantom: PhantomData,
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
