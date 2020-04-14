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

use failure::{
    bail,
    Fallible,
};

use iota_streams_app::message;
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            BasicTbitWord,
            IntTbitWord,
            SpongosTbitWord,
        },
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Announce` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9ANNOUNCE";

pub struct ContentWrap<'a, TW, F, P: mss::Parameters<TW>> {
    pub(crate) mss_sk: &'a mss::PrivateKey<TW, P>,
    pub(crate) ntru_pk: Option<&'a ntru::PublicKey<TW, F>>,
}

impl<'a, TW, F, P: mss::Parameters<TW>, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, F, P>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Fallible<&'c mut sizeof::Context<TW, F>> {
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

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
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

pub struct ContentUnwrap<TW, F, P> {
    pub(crate) mss_pk: mss::PublicKey<TW, P>,
    pub(crate) ntru_pk: Option<ntru::PublicKey<TW, F>>,
}

impl<TW, F, P> Default for ContentUnwrap<TW, F, P>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
{
    fn default() -> Self {
        Self {
            mss_pk: mss::PublicKey::<TW, P>::default(),
            ntru_pk: None,
        }
    }
}

impl<TW, F, P, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<TW, F, P>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>> {
        ctx.absorb(&mut self.mss_pk)?;
        let mut oneof = Trint3(-1);
        ctx.absorb(&mut oneof)?;
        self.ntru_pk = match oneof {
            Trint3(0) => None,
            Trint3(1) => {
                let mut ntru_pk = ntru::PublicKey::default();
                ctx.absorb(&mut ntru_pk)?;
                Some(ntru_pk)
            }
            _ => bail!("Announce: bad oneof: {:?}", oneof),
        };
        ctx.mssig(&self.mss_pk, MssHashSig)?;
        Ok(ctx)
    }
}
