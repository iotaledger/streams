// Rust
use alloc::{
    boxed::Box,
    string::ToString,
    vec::Vec,
};
use core::convert::{
    TryFrom,
    TryInto,
};
use spongos::ddml::commands::X25519;

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
#[cfg(feature = "did")]
use identity::{
    core::{
        decode_b58,
        encode_b58,
    },
    crypto::{
        Ed25519 as DIDEd25519,
        JcsEd25519,
        Named,
        Signature,
        SignatureOptions,
        SignatureValue,
        Signer,
    },
    did::{
        verifiable::VerifierOptions,
        DID as IdentityDID,
    },
    iota::{
        Client as DIDClient,
        IotaDID,
    },
};

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Ed25519,
            Mask,
            Squeeze,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Uint8,
        },
    },
    KeccakF1600,
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::id::did::{
    DIDMethodId,
    DataWrapper,
    DID,
    DID_CORE,
};
use crate::{
    id::psk::{
        Psk,
        PskId,
    },
    message::{
        content::{
            ContentSizeof,
            ContentWrap,
        },
        ContentDecrypt,
        ContentEncrypt,
        ContentEncryptSizeOf,
        ContentUnwrap,
        ContentVerify,
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
pub enum Identifier {
    Ed25519(ed25519::PublicKey),
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
            Identifier::Ed25519(public_key) => public_key.as_slice(),
            Identifier::PskId(id) => id.as_bytes(),
            #[cfg(feature = "did")]
            Identifier::DID(did) => did.as_ref(),
        }
    }

    fn pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::Ed25519(pk) = self {
            Some(pk)
        } else {
            None
        }
    }

    fn is_pub_key(&self) -> bool {
        matches!(self, Self::Ed25519(_))
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
        Identifier::Ed25519(pk)
    }
}

impl From<PskId> for Identifier {
    fn from(pskid: PskId) -> Self {
        Identifier::PskId(pskid)
    }
}

impl From<&Psk> for Identifier {
    fn from(psk: &Psk) -> Self {
        // TODO: REMOVE TYPE PARAMETER OR REMOTE TYPE ARGUMENT ASSUMPTION
        Identifier::PskId(psk.to_pskid::<KeccakF1600>())
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
            Identifier::Ed25519(pk) => {
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
            Identifier::Ed25519(pk) => {
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
impl<'a, F, IS> ContentUnwrap<'a, F, IS> for Identifier
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap<'b>(&'a mut self, ctx: &'b mut unwrap::Context<F, IS>) -> Result<&'b mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8::new(0);
        ctx.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut pk = ed25519::PublicKey::try_from_bytes([0; 32]).unwrap();
                ctx.mask(&mut pk)?;
                *self = Identifier::Ed25519(pk);
            }
            1 => {
                let mut pskid = PskId::default();
                ctx.mask(&mut NBytes::new(&mut pskid))?;
                *self = Identifier::PskId(pskid);
            }
            #[cfg(feature = "did")]
            2 => {
                let mut method_id = DIDMethodId::default();
                ctx.mask(&mut NBytes::new(&mut method_id))?;
                let did = method_id.try_to_did()?;
                *self = Identifier::DID(DIDMethodId::from_did_unsafe(&did));
            }
            o => return Err(anyhow!("{} is not a valid identifier option", o)),
        }
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentVerify<F, IS> for Identifier
where
    F: PRP,
    IS: io::IStream,
{
    async fn verify<'b>(&self, ctx: &'b mut unwrap::Context<F, IS>) -> Result<&'b mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8::default();
        ctx.absorb(&mut oneof)?;
        match oneof.inner() {
            0 => match self {
                Self::Ed25519(public_key) => {
                    let mut hash = External::new(NBytes::new([0; 64]));
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(public_key, &hash)?;
                    Ok(ctx)
                }
                _ => Err(anyhow!("expected Identity type 'Ed25519', found something else")),
            },
            #[cfg(feature = "did")]
            1 => {
                match self {
                    Self::DID(method_id) => {
                        let mut hash = [0; 64];
                        let mut fragment_bytes = Bytes::default();
                        let mut signature_bytes = NBytes::new([0; 64]);

                        ctx.absorb(&mut fragment_bytes)? // TODO: MOVE FRAGMENT TO IDENTIFIER
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?
                            .absorb(&mut signature_bytes)?;

                        let fragment = format!(
                            "#{}",
                            fragment_bytes
                                .as_str()
                                .ok_or_else(|| anyhow!("fragment must be UTF8 encoded"))?
                        );

                        let did_url = method_id.try_to_did()?.join(fragment)?;
                        let mut signature = Signature::new(JcsEd25519::<DIDEd25519>::NAME, did_url.to_string());
                        signature.set_value(SignatureValue::Signature(encode_b58(&signature_bytes)));

                        let data = DataWrapper::new(&hash).with_signature(signature);

                        let doc = DIDClient::new().await?.read_document(did_url.did()).await?;
                        doc.document
                            .verify_data(&data, &VerifierOptions::new())
                            .map_err(|e| {
                                anyhow!("There was an issue validating the signature: {}", e)
                            })?;
                        Ok(ctx)
                    }
                    _ => Err(anyhow!("expected Identity type 'DID', found something else")),
                }
            }
            o => Err(anyhow!("{} is not a valid identity option", o)),
        }
    }
}

// TODO: Find a better way to represent this logic without the need for an additional trait
#[async_trait(?Send)]
impl ContentEncryptSizeOf for Identifier {
    async fn encrypt_sizeof<'a>(
        &self,
        ctx: &'a mut sizeof::Context,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut sizeof::Context> {
        match self {
            Self::PskId(_) => ctx
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), &NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentEncrypt<F, OS> for Identifier
where
    F: PRP,
    OS: io::OStream,
{
    async fn encrypt<'a>(
        &self,
        ctx: &'a mut wrap::Context<F, OS>,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut wrap::Context<F, OS>> {
        match self {
            Self::PskId(_) => ctx
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), &NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}
