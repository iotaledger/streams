// Rust
use alloc::{
    boxed::Box,
    string::{
        String,
        ToString,
    },
    vec::Vec,
};
use core::{
    convert::{
        AsRef,
        TryFrom,
    },
    marker::PhantomData,
};

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

// IOTA-Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Ed25519 as Ed25519Command,
            Mask,
            Squeeze,
            X25519,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Uint8,
        },
    },
    SpongosRng,
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::id::did::{
    DIDInfo,
    DIDMethodId,
    DataWrapper,
    DID,
};
use crate::{
    id::{
        identifier::Identifier,
        psk::{
            Psk,
            PskId,
        },
    },
    message::{
        ContentDecrypt,
        ContentEncrypt,
        ContentEncryptSizeOf,
        ContentSign,
        ContentSignSizeof,
        ContentSizeof,
        ContentVerify,
    },
};

struct KeyPairs {
    sig: (ed25519::SecretKey, ed25519::PublicKey),
    key_exchange: (x25519::SecretKey, x25519::PublicKey),
}

pub struct Ed25519(ed25519::SecretKey);

impl Ed25519 {
    pub fn new(secret: ed25519::SecretKey) -> Self {
        Self(secret)
    }

    pub fn from_seed<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP + Default,
    {
        Self(ed25519::SecretKey::generate_with(&mut SpongosRng::<F>::new(seed)))
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Identity {
    Ed25519(Ed25519),
    Psk(Psk),
    #[cfg(feature = "did")]
    DID(DID),
}

impl Default for Identity {
    fn default() -> Self {
        // unwrap is fine because we are using default
        let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
        let signing_public_key = signing_private_key.public_key();
        let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
        let key_exchange_public_key = key_exchange_private_key.public_key();

        Self::Ed25519(Ed25519(signing_private_key))
    }
}

impl Identity {
    #[deprecated = "to be removed once key exchange is encapsulated within Identity"]
    pub fn _ke_sk(&self) -> Option<x25519::SecretKey> {
        match self {
            Self::Ed25519(Ed25519(ed_secret)) => {
                let x_secret: x25519::SecretKey = ed_secret.into();
                Some(x_secret)
            }
            Self::Psk(_) => None,
            #[cfg(feature = "did")]
            Self::DID(DID::PrivateKey(info)) => Some(info.ke_kp().0),
            // TODO: Account implementation
        }
    }

    #[deprecated = "to be removed once key exchange is encapsulated within Identity"]
    pub fn _ke(&self) -> [u8; 32] {
        match self {
            Self::Psk(psk) => psk.to_bytes(),
            Self::Ed25519(Ed25519(ed_secret)) => {
                let x_secret: x25519::SecretKey = ed_secret.into();
                x_secret.to_bytes()
            }
            #[cfg(feature = "did")]
            Self::DID(DID::PrivateKey(info)) => info.ke_kp().0.to_bytes(),
            // TODO: Account implementation
        }
    }

    pub fn to_identifier(&self) -> Identifier {
        match self {
            Self::Ed25519(Ed25519(secret)) => secret.public_key().into(),
            Self::Psk(psk) => psk.into(),
            #[cfg(feature = "did")]
            Self::DID(did) => did.info().did().into(),
        }
    }
}

impl From<Identity> for Identifier {
    fn from(identity: Identity) -> Self {
        identity.to_identifier()
    }
}

#[async_trait(?Send)]
impl ContentSignSizeof<Identity> for sizeof::Context {
    async fn sign_sizeof(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(Ed25519(secret)) => {
                let hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(&hash)?
                    .ed25519(secret, &hash)?;
                Ok(self)
            }

            Identity::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => match did_impl {
                DID::PrivateKey(info) => {
                    let hash = [0; 64];
                    let key_fragment = info.key_fragment().as_bytes().to_vec();
                    let signature = [0; 64];
                    self.absorb(Uint8::new(1))?
                        .absorb(&Bytes::new(key_fragment))?
                        .commit()?
                        .squeeze(External::new(&NBytes::new(&hash)))?
                        .absorb(&NBytes::new(signature))
                }
            },
        }
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentSign<Identity> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(Ed25519(secret)) => {
                let mut hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(&mut hash)?
                    .ed25519(secret, &hash)?;
                Ok(self)
            }

            Identity::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => {
                match did_impl {
                    DID::PrivateKey(info) => {
                        let mut hash = [0; 64];
                        let key_fragment = info.key_fragment().as_bytes().to_vec();
                        self.absorb(Uint8::new(1))?
                            .absorb(&Bytes::new(key_fragment))?
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?;

                        let mut data = DataWrapper::new(&hash);
                        let fragment = format!("#{}", info.key_fragment());
                        // Join the DID identifier with the key fragment of the verification method
                        let method = info.did().clone().join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(
                            &mut data,
                            method.to_string(),
                            info.keypair().private().as_ref(),
                            SignatureOptions::new(),
                        )?;
                        let signature = decode_b58(
                            &data
                                .into_signature()
                                .ok_or_else(|| {
                                    anyhow!("there was an issue with calculating the signature, cannot wrap message")
                                })?
                                .value()
                                .as_str(),
                        )?;
                        self.absorb(&NBytes::new(signature))
                    } // TODO: Implement Account logic
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentDecrypt<Identity> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn decrypt(&mut self, recipient: &Identity, exchange_key: &[u8], key: &mut [u8]) -> Result<&mut Self> {
        match recipient {
            Identity::Psk(_) => self
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&mut NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introduction)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(byte_array) => self.x25519(&x25519::SecretKey::from_bytes(byte_array), &mut NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}
