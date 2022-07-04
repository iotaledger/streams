// Rust
use alloc::boxed::Box;
use core::convert::{TryFrom, TryInto};
use spongos::ddml::commands::X25519;

// 3rd-party
use anyhow::{anyhow, Result};
use async_trait::async_trait;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};
#[cfg(feature = "did")]
use identity_iota::{
    core::BaseEncoding,
    crypto::{Ed25519 as DIDEd25519, JcsEd25519, Named, Proof, ProofValue},
    did::{verifiable::VerifierOptions, MethodScope, DID as IdentityDID},
    iota_core::IotaDID,
};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519, Mask, Squeeze},
        io,
        modifiers::External,
        types::{NBytes, Uint8},
    },
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::id::did::{resolve_document, DIDUrlInfo, DataWrapper};
use crate::message::{ContentEncrypt, ContentEncryptSizeOf, ContentVerify};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Identifier {
    Ed25519(ed25519::PublicKey),
    #[cfg(feature = "did")]
    DID(DIDUrlInfo),
}

impl core::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ed25519(arg0) => f.debug_tuple("Ed25519").field(&hex::encode(&arg0)).finish(),
            #[cfg(feature = "did")]
            Self::DID(url_info) => f.debug_tuple("DID").field(&url_info.did()).finish(),
        }
    }
}

impl Identifier {
    /// View into the underlying Byte array of the identifier
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Identifier::Ed25519(public_key) => public_key.as_slice(),
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => url_info.did().as_bytes(),
        }
    }

    // #[deprecated = "to be removed once key-exchange is encapsulated within Identity"]
    pub async fn _ke_pk(&self) -> Result<x25519::PublicKey> {
        match self {
            Identifier::Ed25519(pk) => Ok(pk.try_into()?),
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info).await?;
                let method = doc
                    .document
                    .resolve_method(url_info.exchange_fragment(), Some(MethodScope::key_agreement()))
                    .expect("DID Method could not be resolved");
                Ok(x25519::PublicKey::try_from_slice(&method.data().try_decode()?)?)
            }
        }
    }

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

#[cfg(feature = "did")]
impl From<&DIDUrlInfo> for Identifier {
    fn from(did: &DIDUrlInfo) -> Self {
        Identifier::DID(did.clone())
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

impl core::fmt::UpperHex for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{}", hex::encode_upper(self))
    }
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl Mask<&Identifier> for sizeof::Context {
    fn mask(&mut self, identifier: &Identifier) -> Result<&mut Self> {
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
    fn mask(&mut self, identifier: &Identifier) -> Result<&mut Self> {
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
    fn mask(&mut self, identifier: &mut Identifier) -> Result<&mut Self> {
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
            o => return Err(anyhow!("{} is not a valid identifier option", o)),
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
    async fn verify(&mut self, verifier: &Identifier) -> Result<&mut Self> {
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
                _ => Err(anyhow!("expected Identity type 'Ed25519', found something else")),
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
                        fragment_bytes
                            .to_str()
                            .ok_or_else(|| anyhow!("fragment must be UTF8 encoded"))?
                    );

                    let did_url = IotaDID::parse(url_info.did())?.join(signing_fragment)?;
                    let mut signature = Proof::new(JcsEd25519::<DIDEd25519>::NAME, did_url);
                    signature.set_value(ProofValue::Signature(BaseEncoding::encode_base58(&signature_bytes)));

                    let data = DataWrapper::new(&hash).with_signature(signature);

                    let doc = resolve_document(&url_info).await?;
                    doc.document
                        .verify_data(&data, &VerifierOptions::new())
                        .map_err(|e| anyhow!("There was an issue validating the signature: {}", e))?;
                    Ok(self)
                }
                _ => Err(anyhow!("expected Identity type 'DID', found something else")),
            },
            o => Err(anyhow!("{} is not a valid identity option", o)),
        }
    }
}

// TODO: Find a better way to represent this logic without the need for an additional trait
#[async_trait(?Send)]
impl ContentEncryptSizeOf<Identifier> for sizeof::Context {
    async fn encrypt_sizeof(&mut self, recipient: &Identifier, key: &[u8]) -> Result<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introdution)
        match recipient {
            Identifier::Ed25519(pk) => {
                let xkey = x25519::PublicKey::try_from(pk)?;
                self.x25519(&xkey, NBytes::new(key))
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info).await?;
                let method = doc
                    .document
                    .resolve_method(url_info.exchange_fragment(), None)
                    .expect("DID Method could not be resolved");
                let xkey = x25519::PublicKey::try_from_slice(&method.data().try_decode()?)?;
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
    async fn encrypt(&mut self, recipient: &Identifier, key: &[u8]) -> Result<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introdution)
        match recipient {
            Identifier::Ed25519(pk) => {
                let xkey = x25519::PublicKey::try_from(pk)?;
                self.x25519(&xkey, NBytes::new(key))
            }
            #[cfg(feature = "did")]
            Identifier::DID(url_info) => {
                let doc = resolve_document(url_info).await?;
                let method = doc
                    .document
                    .resolve_method(url_info.exchange_fragment(), None)
                    .expect("DID Method could not be resolved");
                let xkey = x25519::PublicKey::try_from_slice(&method.data().try_decode()?)?;
                self.x25519(&xkey, NBytes::new(key))
            }
        }
    }
}
