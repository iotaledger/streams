//! `Announce` message content. This is the initial message of the Channel application instance.
//! It announces channel owner's public keys: MSS and possibly NTRU, and is similar to
//! self-signed certificate in a conventional PKI.
//!
//! ```pb3
//! message Announce {
//!     absorb tryte msspk[81];
//!     absorb oneof {
//!         null empty = 0;
//!         tryte ntrupk[3072] = 1;
//!     }
//!     commit;
//!     squeeze external tryte tag[78];
//!     mssig(tag) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `msspk` -- channel owner's MSS public key.
//!
//! * `empty` -- signifies absence of owner's NTRU public key.
//!
//! * `ntrupk` -- channel owner's NTRU public key.
//!
//! * `tag` -- hash-value to be signed.
//!
//! * `sig` -- signature of `tag` field produced with the MSS private key corresponding to `msspk`.
//!

use anyhow::Result;

use iota_streams_app::message;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Announce` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9ANNOUNCE";

pub struct ContentWrap<'a, F> {
    pub(crate) sig_kp: &'a ed25519::Keypair,
    pub multi_branching: u8,
    pub(crate) _phantom: core::marker::PhantomData<F>,
}

impl<'a, F, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F>
where
    F: PRP,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.sig_kp.public)?;
        ctx.absorb(NBytes::zero(1))?;
        ctx.ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.absorb(&self.sig_kp.public)?;
        ctx.absorb(&NBytes(vec![self.multi_branching]))?;
        ctx.ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) sig_pk: ed25519::PublicKey,
    pub(crate) ke_pk: x25519::PublicKey,
    pub multi_branching: u8,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F> {
    fn default() -> Self {
        let sig_pk = ed25519::PublicKey::default();
        let ke_pk = x25519::public_from_ed25519(&sig_pk);
        Self {
            sig_pk,
            ke_pk,
            multi_branching: 0,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F>
where
    F: PRP,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut input_byte = NBytes::zero(1);
        ctx.absorb(&mut self.sig_pk)?;
        self.ke_pk = x25519::public_from_ed25519(&self.sig_pk);
        ctx.absorb(&mut input_byte)?;
        if input_byte.0[0] == 1_u8 {
            self.multi_branching = 1;
        }
        ctx.ed25519(&self.sig_pk, HashSig)?;
        Ok(ctx)
    }
}
