// Rust
use alloc::{boxed::Box, string::ToString};
use core::{
    convert::AsRef,
    hash::Hash,
};

// 3rd-party
use anyhow::{anyhow, Result};
use async_trait::async_trait;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};
#[cfg(feature = "did")]
use identity_iota::{
    core::BaseEncoding,
    crypto::{Ed25519 as DIDEd25519, JcsEd25519, ProofOptions, Signer},
    did::DID as IdentityDID,
};
use identity_iota::iota_core::IotaDID;

// IOTA-Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519 as Ed25519Command, Mask, Squeeze, X25519},
        io,
        modifiers::External,
        types::{Bytes, NBytes, Uint8},
    },
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::id::did::{DataWrapper, DID};
use crate::{
    id::{ed25519::Ed25519, identifier::Identifier},
    message::{ContentDecrypt, ContentSign, ContentSignSizeof},
};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum Identity {
    Ed25519(Ed25519),
    #[cfg(feature = "did")]
    DID(DID),
}

impl Default for Identity {
    fn default() -> Self {
        // unwrap is fine because we are using default
        let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
        Self::Ed25519(Ed25519::new(signing_private_key))
    }
}

impl Identity {
    // #[deprecated = "to be removed once key exchange is encapsulated within Identity"]
    pub fn _ke_sk(&self) -> x25519::SecretKey {
        match self {
            Self::Ed25519(ed25519) => ed25519.inner().into(),
            #[cfg(feature = "did")]
            Self::DID(DID::PrivateKey(info)) => info.ke_kp().0,
            #[cfg(feature = "did")]
            Self::DID(DID::Default) => unreachable!(),
            // TODO: Account implementation
        }
    }

    pub fn to_identifier(&self) -> Identifier {
        match self {
            Self::Ed25519(ed25519) => ed25519.inner().public_key().into(),
            #[cfg(feature = "did")]
            Self::DID(did) => did.info().url_info().into(),
        }
    }
}

impl From<Ed25519> for Identity {
    fn from(ed25519: Ed25519) -> Self {
        Self::Ed25519(ed25519)
    }
}

#[cfg(feature = "did")]
impl From<DID> for Identity {
    fn from(did: DID) -> Self {
        Self::DID(did)
    }
}

impl From<Identity> for Identifier {
    fn from(identity: Identity) -> Self {
        identity.to_identifier()
    }
}

impl Mask<&Identity> for sizeof::Context {
    fn mask(&mut self, identity: &Identity) -> Result<&mut Self> {
        match identity {
            Identity::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            Identity::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<OS, F> Mask<&Identity> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, identity: &Identity) -> Result<&mut Self> {
        match identity {
            Identity::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            Identity::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<IS, F> Mask<&mut Identity> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, identity: &mut Identity) -> Result<&mut Self> {
        let mut oneof = Uint8::default();
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut ed25519_bytes = [0; ed25519::SECRET_KEY_LENGTH];
                self.mask(NBytes::new(&mut ed25519_bytes))?;
                *identity = Identity::Ed25519(ed25519::SecretKey::from_bytes(ed25519_bytes).into());
                Ok(self)
            }
            #[cfg(feature = "did")]
            1 => {
                let mut did = DID::default();
                self.mask(&mut did)?;
                *identity = Identity::DID(did);
                Ok(self)
            }
            other => Err(anyhow!("'{}' is not a valid identity type", other)),
        }
    }
}

#[async_trait(?Send)]
impl ContentSignSizeof<Identity> for sizeof::Context {
    async fn sign_sizeof(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(ed25519) => {
                let hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_ref())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => match did_impl {
                DID::PrivateKey(info) => {
                    let hash = [0; 64];
                    let key_fragment = info.url_info().signing_fragment().as_bytes().to_vec();
                    let signature = [0; 64];
                    self.absorb(Uint8::new(1))?
                        .absorb(Bytes::new(key_fragment))?
                        .commit()?
                        .squeeze(External::new(&NBytes::new(&hash)))?
                        .absorb(NBytes::new(signature))
                }
                DID::Default => unreachable!(),
            },
        }
    }
}

#[async_trait(?Send)]
impl<OS, F> ContentSign<Identity> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(ed25519) => {
                let mut hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_mut())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => {
                match did_impl {
                    DID::PrivateKey(info) => {
                        let mut hash = [0; 64];
                        let key_fragment = info.url_info().signing_fragment().as_bytes().to_vec();
                        self.absorb(Uint8::new(1))?
                            .absorb(Bytes::new(key_fragment))?
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?;

                        let mut data = DataWrapper::new(&hash);
                        let fragment = format!("#{}", info.url_info().signing_fragment());
                        // Join the DID identifier with the key fragment of the verification method
                        let method = IotaDID::parse(info.url_info().did())?.join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(
                            &mut data,
                            method.to_string(),
                            info.keypair().private().as_ref(),
                            ProofOptions::new(),
                        )?;
                        let signature = BaseEncoding::decode_base58(
                            &data
                                .into_signature()
                                .ok_or_else(|| {
                                    anyhow!("there was an issue with calculating the signature, cannot wrap message")
                                })?
                                .value()
                                .as_str(),
                        )?;
                        self.absorb(NBytes::new(signature))
                    }
                    DID::Default => unreachable!(),
                    // TODO: Implement Account logic
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<IS, F> ContentDecrypt<Identity> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    async fn decrypt(&mut self, recipient: &Identity, key: &mut [u8]) -> Result<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introduction)
        match recipient {
            Identity::Ed25519(kp) => self.x25519(&kp.inner().into(), NBytes::new(key)),
            #[cfg(feature = "did")]
            Identity::DID(did) => self.x25519(&did.info().exchange_key()?, NBytes::new(key))
        }
    }
}
