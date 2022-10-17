// Rust
use alloc::boxed::Box;
use core::convert::{TryFrom, TryInto};
use spongos::ddml::commands::X25519;

// 3rd-party
use async_trait::async_trait;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519, Mask, Squeeze},
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
    id::did::{resolve_document, DIDUrlInfo},
};

use crate::{
    error::Result,
    message::{ContentEncrypt, ContentEncryptSizeOf, ContentVerify},
};

/// User Identification types
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Identifier {
    /// Ed25519 Keypair based identifier
    Ed25519(ed25519::PublicKey),
    /// IOTA DID based identifier
    #[cfg(feature = "did")]
    DID(DIDUrlInfo),
}

impl core::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ed25519(arg0) => f.debug_tuple("Ed25519").field(&hex::encode(&arg0)).finish(),
            #[cfg(feature = "did")]
            Self::DID(url_info) => f
                .debug_tuple("DID")
                .field(&url_info.did())
                .field(&url_info.exchange_fragment())
                .field(&url_info.signing_fragment())
                .finish(),
        }
    }
}

impl Identifier {
    /// View into the underlying Byte array of the identifier
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Identifier::Ed25519(public_key) => public_key.as_slice(),
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => url_info.as_ref(),
        }
    }

    /// Converts the underlying Ed25519 Public Key from the [`Identifier`] into an X25519 Public Key
    /// for key exchange.
    pub async fn ke_pk(&self) -> Result<x25519::PublicKey> {
        match self {
            Identifier::Ed25519(pk) => Ok(pk
                .try_into()
                .expect("failed to convert ed25519 public-key to x25519 public-key")),
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info).await?;
                match doc.document.resolve_method(
                    url_info.exchange_fragment(),
                    Some(identity_iota::did::MethodScope::key_agreement()),
                ) {
                    Some(e) => Ok(x25519::PublicKey::try_from_slice(
                        &e.data().try_decode().map_err(|e| Error::did("try_decode", e))?,
                    )
                    .map_err(|e| Error::Crypto("create the public key from slice", e))?),
                    None => Err(Error::did(
                        "get public key from key exchange",
                        alloc::format!(
                            "DID Method fragment {} could not be resolved",
                            url_info.exchange_fragment()
                        ),
                    )),
                }
            }
        }
    }

    /// Returns whether the [`Identifier`] type is Ed25519 or not
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
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

impl AsRef<[u8]> for Identifier {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

impl core::fmt::UpperHex for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode_upper(self))
    }
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl Mask<&Identifier> for sizeof::Context {
    fn mask(&mut self, identifier: &Identifier) -> SpongosResult<&mut Self> {
        match identifier {
            Identifier::Ed25519(pk) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(pk)?;
                Ok(self)
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(url_info)?;
                Ok(self)
            }
        }
    }
}

impl<OS, F> Mask<&Identifier> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, identifier: &Identifier) -> SpongosResult<&mut Self> {
        match &identifier {
            Identifier::Ed25519(pk) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(pk)?;
                Ok(self)
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(url_info)?;
                Ok(self)
            }
        }
    }
}

impl<IS, F> Mask<&mut Identifier> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, identifier: &mut Identifier) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut pk = ed25519::PublicKey::try_from_bytes([0; 32]).unwrap();
                self.mask(&mut pk)?;
                *identifier = Identifier::Ed25519(pk);
            }
            #[cfg(feature = "did")]
            1 => {
                let mut url_info = DIDUrlInfo::default();
                self.mask(&mut url_info)?;
                *identifier = Identifier::DID(url_info);
            }
            o => return Err(SpongosError::InvalidOption("identifier", o)),
        }
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<IS, F> ContentVerify<Identifier> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    /// Verifies the signature of the message based on the type of [`Identifier`] of the signing
    /// user. If the sender [`Identifier`] is of type [`Identifier::Ed25519`], then the public
    /// key is used to verify the message signature. If it is of type [`Identifier::DID`], then
    /// the `DID` document is retrieved and the signature is verified using the appropriately
    /// tagged `Verification Method`.
    ///
    /// # Arguments
    /// * `verifier`: The [`Identifier`] of the signer.
    async fn verify(&mut self, verifier: &Identifier) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::default();
        self.absorb(&mut oneof)?;
        match oneof.inner() {
            0 => match verifier {
                Identifier::Ed25519(public_key) => {
                    let mut hash = External::new(NBytes::new([0; 64]));
                    self.commit()?
                        .squeeze(hash.as_mut())?
                        .ed25519(public_key, hash.as_ref())?;
                    Ok(self)
                }
                #[cfg(feature = "did")]
                o => Err(SpongosError::InvalidAction(
                    "verify data",
                    o.to_string(),
                    verifier.to_string(),
                )),
            },
            #[cfg(feature = "did")]
            1 => match verifier {
                Identifier::DID(url_info) => {
                    let mut hash = [0; 64];
                    let mut fragment_bytes = spongos::ddml::types::Bytes::default();
                    let mut signature_bytes = [0; 64];

                    self.absorb(fragment_bytes.as_mut())?
                        .commit()?
                        .squeeze(External::new(&mut NBytes::new(&mut hash)))?
                        .absorb(NBytes::new(&mut signature_bytes))?;

                    let signing_fragment = format!(
                        "#{}",
                        fragment_bytes.to_str().ok_or(SpongosError::Context(
                            "ContentVerify",
                            SpongosError::InvalidAction(
                                "make signing_fragment",
                                verifier.to_string(),
                                "Fragment bytes cant be converted to string".to_string()
                            )
                            .to_string()
                        ))?
                    );

                    url_info
                        .verify(&signing_fragment, &signature_bytes, &hash)
                        .await
                        .map_err(|e| SpongosError::Context("ContentVerify", e.to_string()))?;
                    Ok(self)
                }
                o => Err(SpongosError::InvalidAction(
                    "verify data",
                    o.to_string(),
                    verifier.to_string(),
                )),
            },
            o => Err(SpongosError::InvalidOption("identity", o)),
        }
    }
}

// TODO: Find a better way to represent this logic without the need for an additional trait
#[async_trait(?Send)]
impl ContentEncryptSizeOf<Identifier> for sizeof::Context {
    async fn encrypt_sizeof(&mut self, recipient: &Identifier, key: &[u8]) -> SpongosResult<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introdution)
        match recipient {
            Identifier::Ed25519(pk) => {
                let xkey =
                    x25519::PublicKey::try_from(pk).expect("failed to convert ed25519 public-key to x25519 public-key");
                self.x25519(&xkey, NBytes::new(key))
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info)
                    .await
                    .map_err(|e| SpongosError::Context("ContentEncryptSizeOf", e.to_string()))?;
                let method = doc
                    .document
                    .resolve_method(url_info.exchange_fragment(), None)
                    .expect("DID Method could not be resolved");
                let xkey = x25519::PublicKey::try_from_slice(
                    &method
                        .data()
                        .try_decode()
                        .map_err(|e| SpongosError::Context("ContentEncrypt try_decode", e.to_string()))?,
                )
                .map_err(|e| SpongosError::Context("ContentEncrypt x25519::PublicKey try_from_slice", e.to_string()))?;
                self.x25519(&xkey, NBytes::new(key))
            }
        }
    }
}

#[async_trait(?Send)]
impl<OS, F> ContentEncrypt<Identifier> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn encrypt(&mut self, recipient: &Identifier, key: &[u8]) -> SpongosResult<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introdution)
        match recipient {
            Identifier::Ed25519(pk) => {
                let xkey =
                    x25519::PublicKey::try_from(pk).expect("failed to convert ed25519 public-key to x25519 public-key");
                self.x25519(&xkey, NBytes::new(key))
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info)
                    .await
                    .map_err(|e| SpongosError::Context("ContentEncrypt", e.to_string()))?;

                let method = doc
                    .document
                    .resolve_method(url_info.exchange_fragment(), None)
                    .expect("DID Method could not be resolved");
                let xkey = x25519::PublicKey::try_from_slice(
                    &method
                        .data()
                        .try_decode()
                        .map_err(|e| SpongosError::Context("ContentEncrypt try_decode", e.to_string()))?,
                )
                .map_err(|e| SpongosError::Context("ContentEncrypt x25519::PublicKey try_from_slice", e.to_string()))?;
                self.x25519(&xkey, NBytes::new(key))
            }
        }
    }
}
