use crypto::signatures::ed25519;

use iota_streams_core::{
    async_trait,
    err,
    prelude::{
        Box,
        Vec,
    },
    psk::{
        self,
        PskId,
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

use crate::message::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKey),
    PskId(PskId),
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
            Identifier::PskId(id) => id,
        }
    }

    pub fn get_pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self {
            Some(pk)
        } else {
            None
        }
    }

    pub fn is_pub_key(&self) -> bool {
        matches!(self, Self::EdPubKey(_))
    }

    pub fn is_psk(&self) -> bool {
        matches!(self, Self::PskId(_))
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk)
    }
}

impl From<PskId> for Identifier {
    fn from(pskid: PskId) -> Self {
        Identifier::PskId(pskid)
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
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(pskid))?;
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
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(pskid))?;
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
            1 => {
                let mut pskid = PskId::default();
                ctx.mask(<&mut NBytes<psk::PskIdSize>>::from(&mut pskid))?;
                let id = Identifier::PskId(pskid);
                Ok((id, ctx))
            }
            _ => err(BadOneof),
        }
    }
}
