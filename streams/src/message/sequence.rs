//! `Sequence` message _wrapping_ and _unwrapping_.
//! 
//! `Sequence` messages act as a referencing lookup point for messages in a multi-branch tree. They form
//! a sequential chain of all the messages published by one publisher. Each publisher has its own chain
//! of `Sequence` messages. 
//!
//! ```ddml
//! message Sequence {
//!     skip link msgid;
//!     join(msgid);
//!     match identifier:
//!       EdPubKey:
//!         mask            u8  id_type(0);
//!         mask            u8  ed25519_pubkey[32];
//!       PskId:
//!         mask            u8  id_type(1);
//!         mask            u8  psk_id[16];
//!    skip                 u64 seq_num;
//!    absorb               u8  linked_msg_id[12];
//!    commit;
//!    squeeze external     u8  hash[64];
//!    ed25519(hash)        u8  signature[64];   
//! }
//! ```
use crypto::signatures::ed25519;

use lets::{
    id::Identifier,
    message::{
        self,
        HasLink,
    },
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

pub struct ContentWrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) id: Identifier,
    pub seq_num: u64,
    pub(crate) ref_link: &'a <Link as HasLink>::Rel,
}

#[async_trait(?Send)]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + AbsorbFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?;
        let ctx = self.id.sizeof(ctx).await?;
        ctx.skip(Uint64(self.seq_num))?
            .absorb(<&Fallback<<Link as HasLink>::Rel>>::from(self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?;
        let ctx = self.id.wrap(store, ctx).await?;
        ctx.skip(Uint64(self.seq_num))?
            .absorb(<&Fallback<<Link as HasLink>::Rel>>::from(self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) id: Identifier,
    pub(crate) seq_num: Uint64,
    pub(crate) ref_link: <Link as HasLink>::Rel,
}

impl<Link> Default for ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default,
{
    fn default() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            id: ed25519::PublicKey::try_from_bytes([0; 32]).unwrap().into(),
            seq_num: Uint64(0),
            ref_link: <<Link as HasLink>::Rel as Default>::default(),
        }
    }
}

#[async_trait(?Send)]
impl<F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<Link>
where
    F: PRP,
    Link: HasLink,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F> + AbsorbFallback<F>,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.join(store, &mut self.link)?;
        let ctx = self.id.unwrap(store, ctx).await?;
        ctx.skip(&mut self.seq_num)?
            .absorb(<&mut Fallback<<Link as HasLink>::Rel>>::from(&mut self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}
