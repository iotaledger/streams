//! `Announce` message content. This is the initial message of the Channel application instance.
//!
//! It announces channel owner's public keys: Ed25519 signature key and corresponding X25519 key
//! exchange key (derived from Ed25519 public key). The `Announce` message is similar to
//! self-signed certificate in a conventional PKI.
//!
//! ```ddml
//! message Announce {
//!     absorb u8 ed25519pk[32];
//!     commit;
//!     squeeze external u8 tag[32];
//!     ed25519(tag) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `ed25519pk` -- channel owner's Ed25519 public key.
//!
//! * `tag` -- hash-value to be signed.
//!
//! * `sig` -- signature of `tag` field produced with the Ed25519 private key corresponding to ed25519pk`.

use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP,
    Result,
};

use iota_streams_app::{
    id::{
        Identifier,
        KeyPairs,
    },
    message::{
        self,
        ContentSign,
        ContentVerify,
    },
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

pub struct ContentWrap<'a, F> {
    key_pairs: &'a KeyPairs,
    flags: Uint8,
    _phantom: core::marker::PhantomData<F>,
}

impl<'a, F> ContentWrap<'a, F> {
    pub fn new(key_pairs: &'a KeyPairs, flags: u8) -> Self {
        Self {
            key_pairs,
            flags: Uint8(flags),
            _phantom: core::marker::PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F: PRP> message::ContentSizeof<F> for ContentWrap<'a, F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        self.key_pairs.id.sizeof(ctx).await?;
        ctx.absorb(&self.key_pairs.sig_kp.public)?;
        ctx.absorb(&self.flags)?;
        let ctx = self.key_pairs.sizeof(ctx).await?;
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
        self.key_pairs.id.wrap(_store, ctx).await?;
        ctx.absorb(&self.key_pairs.sig_kp.public)?;
        ctx.absorb(&self.flags)?;
        let ctx = self.key_pairs.sign(ctx).await?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) sig_pk: ed25519::PublicKey,
    pub(crate) identifier: Identifier,

    #[allow(dead_code)]
    pub(crate) ke_pk: x25519::PublicKey,
    pub(crate) flags: Uint8,
    kp: KeyPairs,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F> {
    fn default() -> Self {
        let sig_pk = ed25519::PublicKey::default();
        let identifier = Identifier::EdPubKey(sig_pk.into());
        // No need to worry about unwrap since it's operating from default input
        let ke_pk = x25519::public_from_ed25519(&sig_pk).unwrap();
        let flags = Uint8(0);
        Self {
            sig_pk,
            ke_pk,
            flags,
            identifier,
            kp: KeyPairs::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> ContentUnwrap<F> {
    pub fn new(kp: KeyPairs) -> Self {
        Self {
            kp,
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
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        self.identifier.unwrap(store, ctx).await?;
        ctx.absorb(&mut self.sig_pk)?;
        self.kp.set_id(self.identifier);
        self.ke_pk = x25519::public_from_ed25519(&self.sig_pk)?;
        ctx.absorb(&mut self.flags)?;
        let ctx = self.kp.verify(ctx).await?;
        Ok(ctx)
    }
}
