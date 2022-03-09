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
    pub(crate) publisher_private_key: &'a ed25519::SecretKey,
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
        ctx.join(&store, self.link)?
            .absorb(&self.publisher_private_key.public_key())?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .ed25519(self.publisher_private_key, HashSig)?;
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
        ctx.join(store, self.link)?
            .absorb(&self.publisher_private_key.public_key())?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .ed25519(self.publisher_private_key, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Bytes,
    pub(crate) masked_payload: Bytes,
    pub(crate) publisher_public_key: ed25519::PublicKey,
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
            publisher_public_key: ed25519::PublicKey::try_from_bytes([0; 32]).unwrap(),
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
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.publisher_public_key)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .ed25519(&self.publisher_public_key, HashSig)?;
        Ok(ctx)
    }
}
