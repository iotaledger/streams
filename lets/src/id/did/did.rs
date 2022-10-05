// Rust
use core::hash::Hash;

// 3rd-party
use anyhow::{anyhow, Result};

// IOTA
use crypto::{keys::x25519, signatures::ed25519};
use identity_iota::{
    client::{Client as DIDClient, ResolvedIotaDocument},
    crypto::{KeyPair as DIDKeyPair, KeyType},
    iota_core::IotaDID,
};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::NBytes,
    },
    PRP,
};

use crate::id::did::DIDUrlInfo;

/// Fetch the `DID` document from the tangle
///
/// # Arguments
/// * `url_info`: The document details
pub(crate) async fn resolve_document(url_info: &DIDUrlInfo) -> Result<ResolvedIotaDocument> {
    let did_url = IotaDID::parse(url_info.did())?;
    let doc = DIDClient::builder()
        .network(did_url.network()?)
        .primary_node(url_info.client_url(), None, None)?
        .build()
        .await?
        .read_document(&did_url)
        .await?;
    Ok(doc)
}

/// Type of `DID` implementation
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DID {
    // TODO: Add DID Account implementation
    /// Private Key based [`DIDInfo`], manually specifying key pairs
    PrivateKey(DIDInfo),
    Default,
}

impl DID {
    /// Returns a reference to the [`DIDInfo`] if present
    pub(crate) fn info(&self) -> &DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
            Self::Default => unreachable!(),
        }
    }

    /// Returns a mutable reference to the [`DIDInfo`] if present
    fn info_mut(&mut self) -> &mut DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
            Self::Default => unreachable!(),
        }
    }
}

impl Default for DID {
    fn default() -> Self {
        DID::Default
    }
}

impl Mask<&DID> for sizeof::Context {
    fn mask(&mut self, did: &DID) -> Result<&mut Self> {
        self.mask(did.info().url_info())?
            .mask(NBytes::new(did.info().keypair().private()))?
            .mask(NBytes::new(did.info().exchange_keypair().private()))
    }
}

impl<OS, F> Mask<&DID> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, did: &DID) -> Result<&mut Self> {
        self.mask(did.info().url_info())?
            .mask(NBytes::new(did.info().keypair().private()))?
            .mask(NBytes::new(did.info().exchange_keypair().private()))
    }
}

impl<IS, F> Mask<&mut DID> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, did: &mut DID) -> Result<&mut Self> {
        let mut url_info = DIDUrlInfo::default();
        let mut private_key_bytes = [0; ed25519::SECRET_KEY_LENGTH];
        let mut exchange_private_key_bytes = [0; x25519::SECRET_KEY_LENGTH];
        self.mask(&mut url_info)?
            .mask(NBytes::new(&mut private_key_bytes))?
            .mask(NBytes::new(&mut exchange_private_key_bytes))?;

        let keypair = DIDKeyPair::try_from_private_key_bytes(KeyType::Ed25519, &private_key_bytes)
            .map_err(|e| anyhow!("error unmasking DID private key: {}", e))?;
        let xkeypair = DIDKeyPair::try_from_private_key_bytes(KeyType::X25519, &exchange_private_key_bytes)
            .map_err(|e| anyhow!("error unmasking DID exchange private key: {}", e))?;
        *did.info_mut().keypair_mut() = keypair;
        *did.info_mut().exchange_keypair_mut() = xkeypair;

        Ok(self)
    }
}

/// Details of a `DID` implementation
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDInfo {
    /// Document retrieval information
    url_info: DIDUrlInfo,
    /// Iota Identity based KeyPair for signatures
    keypair: KeyPair,
    /// Iota Identity based KeyPair for key exchange
    exchange_keypair: KeyPair,
}

impl DIDInfo {
    /// Creates a new [`DIDInfo`] wrapper around the provided details
    ///
    /// # Arguments
    /// * `url_info`: Document retrieval information
    /// * `keypair`: DID KeyPair for signatures
    /// * `exchange_keypair`: DID KeyPair for key exchange
    pub fn new(url_info: DIDUrlInfo, keypair: DIDKeyPair, exchange_keypair: DIDKeyPair) -> Self {
        Self {
            url_info,
            keypair: KeyPair(keypair),
            exchange_keypair: KeyPair(exchange_keypair),
        }
    }

    /// Returns a reference to the [`DIDUrlInfo`]
    pub fn url_info(&self) -> &DIDUrlInfo {
        &self.url_info
    }

    /// Returns a mutable reference to the [`DIDUrlInfo`]
    pub fn url_info_mut(&mut self) -> &mut DIDUrlInfo {
        &mut self.url_info
    }

    /// Returns a reference to the signature [`DIDKeyPair`]
    pub(crate) fn keypair(&self) -> &DIDKeyPair {
        &self.keypair.0
    }

    /// Returns a mutable reference to the signature [`DIDKeyPair`]
    fn keypair_mut(&mut self) -> &mut DIDKeyPair {
        &mut self.keypair.0
    }

    /// Returns a reference to the key exchange [`DIDKeyPair`]
    fn exchange_keypair(&self) -> &DIDKeyPair {
        &self.exchange_keypair.0
    }

    /// Returns a mutable reference to the key exchange [`DIDKeyPair`]
    fn exchange_keypair_mut(&mut self) -> &mut DIDKeyPair {
        &mut self.exchange_keypair.0
    }

    /// Converts key exchange [`DIDKeyPair`] into an [`x25519::SecretKey`] for native Streams
    /// operations
    pub(crate) fn exchange_key(&self) -> Result<x25519::SecretKey> {
        x25519::SecretKey::try_from_slice(self.exchange_keypair.0.private().as_ref()).map_err(|e| e.into())
    }
}

/// Wrapper for a `DID` based KeyPair
struct KeyPair(identity_iota::crypto::KeyPair);

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.0.type_() == other.0.type_() && self.0.private().as_ref() == other.0.private().as_ref()
    }
}

impl Eq for KeyPair {}

impl PartialOrd for KeyPair {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyPair {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.0.type_(), self.0.private().as_ref()).cmp(&(other.0.type_(), other.0.private().as_ref()))
    }
}

impl Hash for KeyPair {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.type_().hash(state);
        self.0.private().as_ref().hash(state);
    }
}
