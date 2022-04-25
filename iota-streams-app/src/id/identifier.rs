use crypto::signatures::ed25519;

use iota_streams_core::{
    async_trait,
    err,
    prelude::{
        Box,
        Vec,
    },
    sponge::prp::PRP,
    Errors::BadOneof,
    Result,
};

use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

#[cfg(feature = "did")]
use crate::id::{
    DIDSize,
    DIDWrap,
    DID_CORE,
};
#[cfg(feature = "did")]
use identity::{
    core::{
        decode_b58,
        encode_b58,
    },
    did::DID,
    iota::IotaDID,
};
#[cfg(feature = "did")]
use iota_streams_core::prelude::ToString;

use crate::message::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKey),
    #[cfg(feature = "did")]
    DID(DIDWrap),
}

impl Identifier {
    /// Owned vector of the underlying Bytes array of the identifier
    pub fn to_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// View into the underlying Byte array of the identifier
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Identifier::EdPubKey(public_key) => public_key.as_slice(),
            #[cfg(feature = "did")]
            Identifier::DID(did) => did,
        }
    }

    pub fn pk(&self) -> Option<&ed25519::PublicKey> {
        match self {
            Identifier::EdPubKey(pk) => Some(pk),
            #[cfg(feature = "did")]
            _ => None,
        }
    }

    pub fn is_pub_key(&self) -> bool {
        matches!(self, Self::EdPubKey(_))
    }
}

impl Default for Identifier {
    fn default() -> Self {
        let default_public_key = ed25519::PublicKey::try_from_bytes([0; ed25519::PUBLIC_KEY_LENGTH]).unwrap();
        Identifier::from(default_public_key)
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk)
    }
}

#[cfg(feature = "did")]
impl From<&IotaDID> for Identifier {
    fn from(did: &IotaDID) -> Self {
        Identifier::DID(DIDWrap::clone_from_slice(
            &decode_b58(did.method_id()).unwrap_or_default(),
        ))
    }
}

impl AsRef<[u8]> for Identifier {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{}", hex::encode(self))
    }
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        core::fmt::LowerHex::fmt(self, f)
    }
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for Identifier {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(oneof)?.mask(pk)?;
                Ok(ctx)
            }
            #[cfg(feature = "did")]
            Identifier::DID(did) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?.mask(<&NBytes<DIDSize>>::from(did))?;
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
        match self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(oneof)?.mask(pk)?;
                Ok(ctx)
            }
            #[cfg(feature = "did")]
            Identifier::DID(did) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?.mask(<&NBytes<DIDSize>>::from(did))?;
                Ok(ctx)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrap<F, Store> for Identifier {
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let (id, ctx) = Self::unwrap_new(_store, ctx).await?;
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
                let mut pk = ed25519::PublicKey::try_from_bytes([0; 32]).unwrap();
                ctx.mask(&mut pk)?;
                let id = Identifier::EdPubKey(pk);
                Ok((id, ctx))
            }
            #[cfg(feature = "did")]
            1 => {
                let mut did_bytes = NBytes::<DIDSize>::default();
                ctx.mask(&mut did_bytes)?;
                let did_str = DID_CORE.to_string() + &encode_b58(&did_bytes.0);
                let did = IotaDID::parse(did_str)?;
                Ok(((&did).into(), ctx))
            }
            _ => err(BadOneof),
        }
    }
}
