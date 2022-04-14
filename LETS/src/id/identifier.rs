use alloc::{
    boxed::Box,
    vec::Vec,
    string::ToString,
};
use core::convert::TryInto;

use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;
use crypto::signatures::ed25519;
// use generic_array::typenum::U16;
#[cfg(feature = "did")]
use identity::{
    core::{
        decode_b58,
        encode_b58,
    },
    did::DID,
    iota::IotaDID,
};

use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Mask,
        },
        io,
        types::{
            NBytes,
            Uint8,
        },
    },
    PRP,
};

#[cfg(feature = "did")]
use crate::id::did::{
    DIDImpl,
    DIDMethodId,
    DID_CORE,
};
use crate::{
    id::psk::PskId,
    message::content::{
        ContentSizeof,
        ContentUnwrapNew,
        ContentWrap,
    },
};
// TODO: REMOVE
// use iota_streams_core::{
//     async_trait,
//     err,
//     prelude::{
//         Box,
//         Vec,
//     },
//     psk::{
//         self,
//         PskId,
//     },
//     sponge::prp::PRP,
//     Errors::BadOneof,
//     Result,
// };
// use iota_streams_ddml::{
//     command::*,
//     io,
//     types::*,
// };
// #[cfg(feature = "did")]
// use iota_streams_core::prelude::ToString;

// TODO: REMOVE
// use crate::message::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub(crate) enum Identifier {
    EdPubKey(ed25519::PublicKey),
    PskId(PskId),
    #[cfg(feature = "did")]
    DID(DIDMethodId),
}

impl Identifier {
    /// Owned vector of the underlying Bytes array of the identifier
    fn to_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// View into the underlying Byte array of the identifier
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Identifier::EdPubKey(public_key) => public_key.as_slice(),
            Identifier::PskId(id) => id.as_bytes(),
            #[cfg(feature = "did")]
            Identifier::DID(did) => did.as_ref(),
        }
    }

    fn pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self {
            Some(pk)
        } else {
            None
        }
    }

    fn is_pub_key(&self) -> bool {
        matches!(self, Self::EdPubKey(_))
    }

    fn is_psk(&self) -> bool {
        matches!(self, Self::PskId(_))
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

impl From<PskId> for Identifier {
    fn from(pskid: PskId) -> Self {
        Identifier::PskId(pskid)
    }
}

#[cfg(feature = "did")]
impl From<&IotaDID> for Identifier {
    fn from(did: &IotaDID) -> Self {
        Identifier::DID(DIDMethodId::from_did_unsafe(did))
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
impl<'a> ContentSizeof<'a> for Identifier {
    async fn sizeof<'b>(&'a self, ctx: &'b mut sizeof::Context) -> Result<&'b mut sizeof::Context> {
        match self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8::new(0);
                ctx.mask(oneof)?.mask(pk)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8::new(1);
                ctx.mask(oneof)?.mask(&NBytes::new(pskid))?;
                Ok(ctx)
            }
            #[cfg(feature = "did")]
            Identifier::DID(did) => {
                let oneof = Uint8::new(2);
                ctx.mask(oneof)?.mask(&NBytes::new(did))?;
                Ok(ctx)
            }
        }
    }
}

#[async_trait(?Send)]
impl<'a, F, OS> ContentWrap<'a, F, OS> for Identifier
where
    F: PRP,
    OS: io::OStream,
{
    async fn wrap<'b>(&'a self, ctx: &'b mut wrap::Context<F, OS>) -> Result<&'b mut wrap::Context<F, OS>> {
        match self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8::new(0);
                ctx.mask(oneof)?.mask(pk)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8::new(1);
                ctx.mask(oneof)?.mask(&NBytes::new(pskid))?;
                Ok(ctx)
            }
            #[cfg(feature = "did")]
            Identifier::DID(did) => {
                let oneof = Uint8::new(2);
                ctx.mask(oneof)?.mask(&NBytes::new(did))?;
                Ok(ctx)
            }
        }
    }
}

// TODO: REMOVE
// #[async_trait(?Send)]
// impl<F: PRP, Store> ContentUnwrap<F, Store> for Identifier {
//     async fn unwrap<'c, IS: io::IStream>(
//         &mut self,
//         _store: &Store,
//         ctx: &'c mut unwrap::Context<F, IS>,
//     ) -> Result<&'c mut unwrap::Context<F, IS>> {
//         let (id, ctx) = Self::unwrap_new(_store, ctx).await?;
//         *self = id;
//         Ok(ctx)
//     }
// }

#[async_trait(?Send)]
impl<F, IS> ContentUnwrapNew<F, IS> for Identifier
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap_new<'c>(ctx: &'c mut unwrap::Context<F, IS>) -> Result<(Self, &'c mut unwrap::Context<F, IS>)> {
        let mut oneof = Uint8::new(0);
        ctx.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut pk = ed25519::PublicKey::try_from_bytes([0; 32]).unwrap();
                ctx.mask(&mut pk)?;
                let id = Identifier::EdPubKey(pk);
                Ok((id, ctx))
            }
            1 => {
                let mut pskid = PskId::default();
                ctx.mask(&mut NBytes::new(&mut pskid))?;
                let id = Identifier::PskId(pskid);
                Ok((id, ctx))
            }
            #[cfg(feature = "did")]
            2 => {
                let mut method_id = DIDMethodId::default();
                ctx.mask(&mut NBytes::new(&mut method_id))?;
                let did = method_id.try_to_did()?;
                let id = Identifier::DID(DIDMethodId::from_did_unsafe(&did));
                Ok((id, ctx))
            }
            o => Err(anyhow!("{} is not a valid identifier option", o)),
        }
    }
}
