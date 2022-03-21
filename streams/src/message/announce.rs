//! `Announce` message _wrapping_ and _unwrapping_.
//! 
//! The `Announce` message is the _genesis_ message of a Stream.
//!
//! It announces the stream owner's identifier. The `Announce` message is similar to
//! a self-signed certificate in a conventional PKI.
//!
//! ```ddml
//! message Announce {
//!     absorb           u8     identifier[32];
//!     absorb           u8     flags;
//!     commit;
//!     squeeze          u8     hash[64];
//!     ed25519(hash)           sig;
//! }
//! ```
use core::marker::PhantomData;

use crypto::signatures::ed25519;

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     Result,
// };

use lets::message;
use spongos::sponge::prp::PRP;
// use iota_streams_ddml::{
//     command::*,
//     io,
//     types::*,
// };

pub struct ContentWrap<'a, F> {
    user_id: &'a UserIdentity<F>,
    flags: Uint8,
    _phantom: PhantomData<F>,
}

impl<'a, F> ContentWrap<'a, F> {
    pub fn new(user_id: &'a UserIdentity<F>, flags: u8) -> Self {
        Self {
            user_id,
            flags: Uint8(flags),
            _phantom: PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F: PRP> message::ContentSizeof<F> for ContentWrap<'a, F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let mut ctx = self
            .user_id
            .id
            .sizeof(ctx)
            .await?
            .absorb(&self.user_id.ke_kp()?.1)?
            .absorb(self.flags)?;
        ctx = self.user_id.sizeof(ctx).await?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<'a, F: PRP, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F> {
    async fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        let mut ctx = self
            .user_id
            .id
            .wrap(_store, ctx)
            .await?
            .absorb(&self.user_id.ke_kp()?.1)?
            .absorb(self.flags)?;
        ctx = self.user_id.sign(ctx).await?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) author_id: UserIdentity<F>,
    #[allow(dead_code)]
    pub(crate) ke_pk: x25519::PublicKey,
    pub(crate) flags: Uint8,
    _phantom: PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F> {
    fn default() -> Self {
        let sig_pk = ed25519::PublicKey::try_from_bytes([0; ed25519::PUBLIC_KEY_LENGTH]).unwrap();
        // No need to worry about unwrap since it's operating from default input
        let ke_pk = x25519::PublicKey::from_bytes(sig_pk.to_bytes());
        let user_id = UserIdentity::default();
        let flags = Uint8(0);
        Self {
            author_id: user_id,
            ke_pk,
            flags,
            _phantom: PhantomData,
        }
    }
}

impl<F> ContentUnwrap<F> {
    pub fn new(user_id: UserIdentity<F>) -> Self {
        Self {
            author_id: user_id,
            ..Default::default()
        }
    }
}

#[async_trait(?Send)]
impl<F, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F>
where
    F: PRP,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut ctx = self
            .author_id
            .id
            .unwrap(_store, ctx)
            .await?
            .absorb(&mut self.ke_pk)?
            .absorb(&mut self.flags)?;
        ctx = self.author_id.verify(ctx).await?;
        Ok(ctx)
    }
}
