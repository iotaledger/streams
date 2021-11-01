use iota_streams_core::{
    async_trait,
    err,
    Errors::BadOneof,
    prelude::{
        Box,
        Vec,
    },
    psk::{
        self,
        PskId
    },
    Result,
    sponge::prp::PRP,
};
#[cfg(feature="use-did")]
use iota_streams_core::{
    iota_identity::{
        iota::IotaDID,
        core::{decode_b58, encode_b58},
    },
    prelude::ToString,
};
use iota_streams_core_edsig::signature::ed25519;
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};


#[cfg(feature = "use-did")]
use crate::id::{DIDWrap, DID_CORE, DIDSize};

use crate::message::*;
use core::fmt::{Display, Formatter};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKeyWrap),
    PskId(PskId),
    #[cfg(feature="use-did")]
    DID(DIDWrap),
}

impl Identifier {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Identifier::EdPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::PskId(id) => id.to_vec(),
            #[cfg(feature = "use-did")]
            Identifier::DID(id) => id.as_slice().to_vec(),
        }
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk.into())
    }
}

impl From<PskId> for Identifier {
    fn from(pskid: PskId) -> Self {
        Identifier::PskId(pskid)
    }
}

#[cfg(feature="use-did")]
impl From<&IotaDID> for Identifier {
    fn from(did: &IotaDID) -> Self {
        Identifier::DID(DIDWrap::clone_from_slice(&decode_b58(did.method_id()).unwrap_or(Vec::new())))
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Identifier({})",
            hex::encode(self.to_bytes())
        )
    }
}


#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for Identifier {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match *self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(&pk.0)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
                Ok(ctx)
            }
            #[cfg(feature="use-did")]
            Identifier::DID(did) => {
                let oneof = Uint8(2);
                ctx.mask(&oneof)?.mask(<&NBytes<DIDSize>>::from(&did))?;
                Ok(ctx)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentWrap<F, Store> for Identifier {
    async fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match *self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(&pk.0)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
                Ok(ctx)
            }
            #[cfg(feature="use-did")]
            Identifier::DID(did) => {
                let oneof = Uint8(2);
                ctx.mask(&oneof)?.mask(<&NBytes<DIDSize>>::from(&did))?;
                Ok(ctx)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrap<F, Store> for Identifier {
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let (id, ctx) = Self::unwrap_new(store, ctx).await?;
        *self = id;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrapNew<F, Store> for Identifier {
    async fn unwrap_new<'c, IS: io::IStream>(
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)> {
        let mut oneof = Uint8(0);
        ctx.mask(&mut oneof)?;
        match oneof.0 {
            0 => {
                let mut pk = ed25519::PublicKey::default();
                ctx.mask(&mut pk)?;
                let id = Identifier::EdPubKey(ed25519::PublicKeyWrap(pk));
                Ok((id, ctx))
            }
            1 => {
                let mut pskid = PskId::default();
                ctx.mask(<&mut NBytes<psk::PskIdSize>>::from(&mut pskid))?;
                let id = Identifier::PskId(pskid);
                Ok((id, ctx))
            }
            #[cfg(feature="use-did")]
            2 => {
                let mut did_bytes = NBytes::<DIDSize>::default();
                ctx.mask(&mut did_bytes)?;
                let mut did = DID_CORE.to_string();
                did.push_str(&encode_b58(&did_bytes.0));
                let id = IotaDID::parse(did)?;
                Ok(((&id).into(), ctx))
            }
            _ => err(BadOneof),
        }
    }
}
