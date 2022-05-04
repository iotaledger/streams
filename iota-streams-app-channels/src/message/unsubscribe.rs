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
use iota_streams_core_edsig::signature::ed25519;
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
    pub(crate) sig_kp: &'a ed25519::Keypair,
    pub(crate) _phantom: PhantomData<(F, Link)>,
}

#[async_trait]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: PRP + Send + Sync,
    Link: HasLink + Send + Sync,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + Send + Sync,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?
            .absorb(&self.sig_kp.public)?
            .commit()?
            .ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }
}

#[async_trait]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: PRP + Send + Sync,
    Link: HasLink + Send + Sync,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + Send + Sync,
    Store: LinkStore<F, <Link as HasLink>::Rel> + Sync,
{
    async fn wrap<'c, OS: io::OStream + Send>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?
            .absorb(&self.sig_kp.public)?
            .commit()?
            .ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }
}

#[derive(Default)]
pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) sig_pk: ed25519::PublicKey,
    _phantom: PhantomData<(F, Link)>,
}

#[async_trait]
impl<F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F, Link>
where
    F: PRP + Send + Sync,
    Link: HasLink + Send + Sync,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F> +Send + Sync,
    Store: LinkStore<F, <Link as HasLink>::Rel> + Sync,
{
    async fn unwrap<'c, IS: io::IStream + Send>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.sig_pk)?
            .commit()?
            .ed25519(&self.sig_pk, HashSig)?;
        Ok(ctx)
    }
}
