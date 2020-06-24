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

use anyhow::{
    bail,
    Result,
};

use iota_streams_app::message;
use iota_streams_core::{
    sponge::prp::PRP,
};
use iota_streams_core_edsig::{signature::ed25519, key_exchange::x25519};
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Announce` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9ANNOUNCE";

pub struct ContentWrap<'a, F> {
    pub(crate) sig_sk: &'a ed25519::SecretKey,
    pub(crate) ke_pk: Option<&'a x25519::PublicKey>,
    _phantom: std::marker::PhantomData<F>,
}

impl<'a, F, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F>
where
    F: PRP,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        //TODO: ctx.absorb(self.sig_sk.public_key())?;
        let oneof: Uint8;
        if let Some(ke_pk) = self.ke_pk {
            oneof = Uint8(1);
            ctx.absorb(&oneof)?.absorb(ke_pk)?;
        } else {
            oneof = Uint8(0);
            ctx.absorb(&oneof)?;
        }
        //TODO: ctx.mssig(self.sig_sk, MssHashSig)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        //TODO: ctx.absorb(self.sig_sk.public_key())?;
        let oneof: Uint8;
        if let Some(ke_pk) = self.ke_pk {
            oneof = Uint8(1);
            ctx.absorb(&oneof)?.absorb(ke_pk)?;
        } else {
            oneof = Uint8(0);
            ctx.absorb(&oneof)?;
        }
        //TODO: ctx.mssig(self.sig_sk, MssHashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) sig_pk: ed25519::PublicKey,
    pub(crate) ke_pk: Option<x25519::PublicKey>,
    _phantom: std::marker::PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F>
{
    fn default() -> Self {
        Self {
            sig_pk: ed25519::PublicKey::default(),
            ke_pk: None,
            _phantom: std::marker::PhantomData,
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
        ctx.absorb(&mut self.sig_pk)?;
        let mut oneof = Uint8(0);
        ctx.absorb(&mut oneof)?;
        self.ke_pk = match oneof {
            Uint8(0) => None,
            Uint8(1) => {
                panic!("not implemented");
                /*
                let mut ke_pk = x25519::PublicKey::default();
                ctx.absorb(&mut ke_pk)?;
                Some(ke_pk)
                 */
            }
            _ => bail!("Announce: bad oneof: {:?}", oneof),
        };
        //ctx.mssig(&self.sig_pk, MssHashSig)?;
        Ok(ctx)
    }
}
