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

use failure::bail;

use iota_mam_core::{signature::mss, key_encapsulation::ntru};
use iota_mam_protobuf3::{command::*, io, types::*};
use crate::Result;

use crate::core::msg;

/// Type of `Announce` message content.
pub const TYPE: &str = "MAM9CHANNEL9ANNOUNCE";

pub struct ContentWrap<'a> {
    pub(crate) mss_sk: &'a mss::PrivateKey,
    pub(crate) ntru_pk: Option<&'a ntru::PublicKey>,
}

impl<'a, Store> msg::ContentWrap<Store> for ContentWrap<'a> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        ctx.absorb(self.mss_sk.public_key())?;
        let oneof: Trint3;
        if let Some(ntru_pk) = self.ntru_pk {
            oneof = Trint3(1);
            ctx.absorb(&oneof)?.absorb(ntru_pk)?;
        } else {
            oneof = Trint3(0);
            ctx.absorb(&oneof)?;
        }
        ctx.mssig(self.mss_sk, MssHashSig)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(&self, _store: &Store, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        ctx.absorb(self.mss_sk.public_key())?;
        let oneof: Trint3;
        if let Some(ntru_pk) = self.ntru_pk {
            oneof = Trint3(1);
            ctx.absorb(&oneof)?.absorb(ntru_pk)?;
        } else {
            oneof = Trint3(0);
            ctx.absorb(&oneof)?;
        }
        ctx.mssig(self.mss_sk, MssHashSig)?;
        Ok(ctx)
    }
}

#[derive(Default)]
pub struct ContentUnwrap {
    pub(crate) mss_pk: mss::PublicKey,
    pub(crate) ntru_pk: Option<ntru::PublicKey>,
}

impl<Store> msg::ContentUnwrap<Store> for ContentUnwrap {
    fn unwrap<'c, IS: io::IStream>(&mut self, store: &Store, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        ctx.absorb(&mut self.mss_pk)?;
        let mut oneof = Trint3(-1);
        ctx.absorb(&mut oneof)?;
        self.ntru_pk = match oneof {
            Trint3(0) => { None },
            Trint3(1) => {
                let mut ntru_pk = ntru::PublicKey::default();
                ctx.absorb(&mut ntru_pk)?;
                Some(ntru_pk)
            },
            _ => { bail!("Announce: bad oneof: {:?}", oneof) }
        };
        ctx.mssig(&self.mss_pk, MssHashSig)?;
        Ok(ctx)
    }
}
