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
    author_private_key: &'a ed25519::SecretKey,
    flags: Uint8,
    _phantom: PhantomData<F>,
}

impl<'a, F> ContentWrap<'a, F> {
    pub fn new(author_private_key: &'a ed25519::SecretKey, flags: u8) -> Self {
        Self {
            author_private_key,
            elags: Uint8(flags),
            _phantom: PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F: PRP> message::ContentSizeof<F> for ContentWrap<'a, F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.author_private_key.public_key())?;
        ctx.absorb(self.flags)?;
        ctx.ed25519(self.author_private_key, HashSig)?;
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
        ctx.absorb(&self.author_private_key.public_key())?;
        ctx.absorb(self.flags)?;
        ctx.ed25519(self.author_private_key, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) author_public_key: ed25519::PublicKey,
    pub(crate) flags: Uint8,
    _phantom: PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F> {
    fn default() -> Self {
        let author_public_key = ed25519::PublicKey::try_from_bytes([0; 32]).unwrap();
        let flags = Uint8(0);
        Self {
            author_public_key,
            flags,
            _phantom: PhantomData,
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
        ctx.absorb(&mut self.author_public_key)?;
        ctx.absorb(&mut self.flags)?;
        ctx.ed25519(&self.author_public_key, HashSig)?;
        Ok(ctx)
    }
}
