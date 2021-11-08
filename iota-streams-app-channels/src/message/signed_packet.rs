//! `SignedPacket` message content. This message contains a plain and masked payload, signed by the
//! sender.
//!
//! The message may be linked to any other message in the channel. It contains both plain and masked
//! payloads. Each packet is signed by the sender's corresponding ed25519 private key for
//! validation.
//!
//! ```ddml
//! message SignedPacket {
//!     join link msgid;
//!     absorb bytes public_payload;
//!     mask bytes masked_payload;
//!     commit;
//!     squeeze external byte hash[78];
//!     mssig(hash) sig;
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
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with the senders private key.

use iota_streams_app::{
    id::{
        Identifier,
        KeyPairs,
    },
    message::{
        self,
        ContentSign,
        ContentVerify,
        HasLink,
    },
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

pub struct ContentWrap<'a, F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Bytes,
    pub(crate) masked_payload: &'a Bytes,
    pub(crate) key_pair: &'a KeyPairs,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
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
        self.key_pair
            .id
            .sizeof(ctx)
            .await?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?;
        self.key_pair.sizeof(ctx).await?;
        // TODO: Is both public and masked payloads are ok? Leave public only or masked only?
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
        self.key_pair
            .id
            .wrap(store, ctx)
            .await?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?;
        self.key_pair.sign(ctx).await?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Bytes,
    pub(crate) masked_payload: Bytes,
    pub(crate) id: Identifier,
    kp: KeyPairs,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<F, Link> ContentUnwrap<F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(kp: KeyPairs) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Bytes::default(),
            masked_payload: Bytes::default(),
            id: ed25519::PublicKey::default().into(),
            kp,
            _phantom: core::marker::PhantomData,
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
        ctx.join(store, &mut self.link)?;
        let mut ctx = self
            .id
            .unwrap(store, ctx)
            .await?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?;
        self.kp.set_id(self.id);
        ctx = self.kp.verify(ctx).await?;
        Ok(ctx)
    }
}
