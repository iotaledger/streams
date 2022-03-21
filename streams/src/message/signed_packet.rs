//! `SignedPacket` message _wrapping_ and _unwrapping_.
//! 
//! `SignedPacket` messages contain a plain and a masked payload, signed by the sender.
//!
//! ```ddml
//! message SignedPacket {
//!     skip                link    msgid;
//!     join(msgid);
//!     absorb              u8      ed25519_pubkey[32];
//!     absorb              uint    public_size;
//!     absorb              u8      public_payload[public_size];
//!     mask                uint    masked_size;
//!     mask                u8      masked_payload[masked_size];
//!     commit;
//!     squeeze external    u8      hash[64];
//!     ed25519(hash)       u8      signature[64];
//! }
//! ```
use core::marker::PhantomData;

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

pub struct ContentWrap<'a, F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Bytes,
    pub(crate) masked_payload: &'a Bytes,
    pub(crate) user_id: &'a UserIdentity<F>,
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
        self.user_id
            .id
            .sizeof(ctx)
            .await?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?;
        let ctx = self.user_id.sizeof(ctx).await?;
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
        self.user_id
            .id
            .wrap(store, ctx)
            .await?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?;
        let ctx = self.user_id.sign(ctx).await?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Bytes,
    pub(crate) masked_payload: Bytes,
    pub(crate) user_id: UserIdentity<F>,
    pub(crate) _phantom: PhantomData<(F, Link)>,
}

impl<F, Link> Default for ContentUnwrap<F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    fn default() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Bytes::default(),
            masked_payload: Bytes::default(),
            user_id: UserIdentity::default(),
            _phantom: PhantomData,
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
        self.user_id
            .id
            .unwrap(store, ctx)
            .await?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?;
        let ctx = self.user_id.verify(ctx).await?;
        Ok(ctx)
    }
}
