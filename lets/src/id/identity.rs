// Rust
use alloc::boxed::Box;
use core::{hash::Hash, ops::Deref};

// 3rd-party
use async_trait::async_trait;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};

#[cfg(feature = "did")]
use identity_iota::{
    core::BaseEncoding,
    crypto::{Ed25519 as DIDEd25519, JcsEd25519, ProofOptions, Signer},
    did::DID as IdentityDID,
    iota_core::IotaDID,
};

// IOTA-Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519 as Ed25519Command, Mask, Squeeze, X25519},
        io,
        modifiers::External,
        types::{NBytes, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::{
    alloc::string::ToString,
    error::Error,
    id::did::{DataWrapper, DID},
};

use crate::{
    error::Result,
    id::{ed25519::Ed25519, identifier::Identifier},
    message::{ContentDecrypt, ContentSign, ContentSignSizeof},
};

/// Wrapper around [`Identifier`], specifying which type of [`Identity`] is being used. An
/// [`Identity`] is the foundation of message sending and verification.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::large_enum_variant)]
pub struct Identity {
    /// Type of User Identity
    identitykind: IdentityKind,
    /// User Identifier
    identifier: Identifier,
}

impl Default for Identity {
    fn default() -> Self {
        Identity::new(IdentityKind::default())
    }
}

impl Identity {
    /// Create a new [`Identity`] from the provided `IdentityKind` wrapper
    ///
    /// # Arguments
    /// * `identity_kind`: A wrapper containing [`Identity`] details
    pub fn new(identity_kind: IdentityKind) -> Self {
        let identifier = identity_kind.to_identifier();
        Self {
            identitykind: identity_kind,
            identifier,
        }
    }

    /// Returns a reference to the User [`Identifier`]
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }
}

impl Deref for Identity {
    type Target = IdentityKind;
    fn deref(&self) -> &Self::Target {
        &self.identitykind
    }
}

impl From<IdentityKind> for Identity {
    fn from(identitykind: IdentityKind) -> Self {
        Self::new(identitykind)
    }
}

impl From<Ed25519> for Identity {
    fn from(ed25519: Ed25519) -> Self {
        Self::new(IdentityKind::Ed25519(ed25519))
    }
}

#[cfg(feature = "did")]
impl From<DID> for Identity {
    fn from(did: DID) -> Self {
        Self::new(IdentityKind::DID(did))
    }
}

/// Wrapper for [`Identity`] details
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum IdentityKind {
    /// An Ed25519 type [`Identity`] using a private key
    Ed25519(Ed25519),
    /// An IOTA `DID` type [`Identity`] using a `DID` document stored in the tangle
    #[cfg(feature = "did")]
    DID(DID),
}

impl Default for IdentityKind {
    fn default() -> Self {
        // unwrap is fine because we are using default
        let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
        Self::Ed25519(Ed25519::new(signing_private_key))
    }
}

impl IdentityKind {
    /// Returns the Secret key part of the key exchange of the Identity
    pub fn ke_sk(&self) -> Result<x25519::SecretKey> {
        match self {
            Self::Ed25519(ed25519) => Ok(ed25519.inner().into()),
            #[cfg(feature = "did")]
            Self::DID(DID::PrivateKey(info)) => Ok(info.exchange_key()?),
            #[cfg(feature = "did")]
            Self::DID(DID::Default) => unreachable!(),
            // TODO: Account implementation
        }
    }

    /// Converts the [`IdentityKind`] instance into an [`Identifier`]
    pub fn to_identifier(&self) -> Identifier {
        match self {
            Self::Ed25519(ed25519) => ed25519.inner().public_key().into(),
            #[cfg(feature = "did")]
            Self::DID(did) => Identifier::DID(did.info().url_info().clone()),
        }
    }
}

impl Mask<&Identity> for sizeof::Context {
    fn mask(&mut self, identity: &Identity) -> SpongosResult<&mut Self> {
        match &identity.identitykind {
            IdentityKind::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<OS, F> Mask<&Identity> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, identity: &Identity) -> SpongosResult<&mut Self> {
        match &identity.identitykind {
            IdentityKind::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<IS, F> Mask<&mut Identity> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, identity: &mut Identity) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::default();
        self.mask(&mut oneof)?;
        let identitykind = match oneof.inner() {
            0 => {
                let mut ed25519_bytes = [0; ed25519::SECRET_KEY_LENGTH];
                self.mask(NBytes::new(&mut ed25519_bytes))?;
                IdentityKind::Ed25519(ed25519::SecretKey::from_bytes(ed25519_bytes).into())
            }
            #[cfg(feature = "did")]
            1 => {
                let mut did = DID::default();
                self.mask(&mut did)?;
                IdentityKind::DID(did)
            }
            o => return Err(SpongosError::InvalidOption("identitykind", o)),
        };

        *identity = Identity::new(identitykind);
        Ok(self)
    }
}

#[async_trait(?Send)]
impl ContentSignSizeof<Identity> for sizeof::Context {
    async fn sign_sizeof(&mut self, signer: &Identity) -> SpongosResult<&mut Self> {
        match &signer.identitykind {
            IdentityKind::Ed25519(ed25519) => {
                let hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_ref())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            IdentityKind::DID(did_impl) => match did_impl {
                DID::PrivateKey(info) => {
                    let hash = [0; 64];
                    let key_fragment = info.url_info().signing_fragment().as_bytes().to_vec();
                    let signature = [0; 64];
                    self.absorb(Uint8::new(1))?
                        .absorb(spongos::ddml::types::Bytes::new(key_fragment))?
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
impl<OS, F> ContentSign<IdentityKind> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign(&mut self, signer: &IdentityKind) -> SpongosResult<&mut Self> {
        match signer {
            IdentityKind::Ed25519(ed25519) => {
                let mut hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_mut())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            IdentityKind::DID(did_impl) => {
                match did_impl {
                    DID::PrivateKey(info) => {
                        let mut hash = [0; 64];
                        let key_fragment = info.url_info().signing_fragment().as_bytes().to_vec();
                        self.absorb(Uint8::new(1))?
                            .absorb(spongos::ddml::types::Bytes::new(key_fragment))?
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?;

                        let mut data = DataWrapper::new(&hash);
                        let fragment = format!("#{}", info.url_info().signing_fragment());
                        // Join the DID identifier with the key fragment of the verification method
                        let method = IotaDID::parse(info.url_info().did())
                            .map_err(|e| SpongosError::Context("ContentSign", Error::did("did parse", e).to_string()))?
                            .join(&fragment)
                            .map_err(|e| {
                                SpongosError::Context("ContentSign", Error::did("join did fragments", e).to_string())
                            })?;

                        JcsEd25519::<DIDEd25519>::create_signature(
                            &mut data,
                            method,
                            info.keypair().private().as_ref(),
                            ProofOptions::new(),
                        )
                        .map_err(|e| {
                            SpongosError::Context("ContentSign for create_signature on JcsEd25519", e.to_string())
                        })?;

                        let signature = BaseEncoding::decode_base58(
                            &data
                                .into_signature()
                                .ok_or(SpongosError::Context(
                                    "ContentSign",
                                    "Missing did signature proof".to_string(),
                                ))?
                                .value()
                                .as_str(),
                        )
                        .map_err(|e| SpongosError::Context("ContentSign", e.to_string()))?;
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
    async fn decrypt(&mut self, recipient: &Identity, key: &mut [u8]) -> SpongosResult<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introduction)
        match &recipient.identitykind {
            IdentityKind::Ed25519(kp) => self.x25519(&kp.inner().into(), NBytes::new(key)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => self.x25519(
                &did.info()
                    .exchange_key()
                    .map_err(|e| SpongosError::Context("ContentDecrypt", e.to_string()))?,
                NBytes::new(key),
            ),
        }
    }
}
