// Rust
use core::hash::Hash;

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
    error::{
        Result as SpongosResult,
        Error as SpongosError,
    },
};

use crate::{
    alloc::string::ToString,
    error::{Error, Result},
    id::did::DIDUrlInfo,
};

pub(crate) async fn resolve_document(url_info: &DIDUrlInfo) -> Result<ResolvedIotaDocument> {
    let did_url = IotaDID::parse(url_info.did()).map_err(|e| Error::did("parse did", e))?;
    let doc = DIDClient::builder()
        .network(did_url.network().map_err(|e| Error::did("DIDClient network", e))?)
        .primary_node(url_info.client_url(), None, None).map_err(|e| Error::did("DIDClient set primary_node", e))?
        .build()
        .await.map_err(|e| Error::did("DIDClient build", e))?
        .read_document(&did_url)
        .await.map_err(|e| Error::did("DIDClient read_doc", e))?;
    Ok(doc)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DID {
    // TODO: Add DID Account implementation
    PrivateKey(DIDInfo),
    Default,
}

impl DID {
    pub(crate) fn info(&self) -> &DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
            Self::Default => unreachable!(),
        }
    }

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
    fn mask(&mut self, did: &DID) -> SpongosResult<&mut Self> {
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
    fn mask(&mut self, did: &DID) -> SpongosResult<&mut Self> {
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
    fn mask(&mut self, did: &mut DID) -> SpongosResult<&mut Self> {
        let mut url_info = DIDUrlInfo::default();
        let mut private_key_bytes = [0; ed25519::SECRET_KEY_LENGTH];
        let mut exchange_private_key_bytes = [0; x25519::SECRET_KEY_LENGTH];
        self.mask(&mut url_info)?
            .mask(NBytes::new(&mut private_key_bytes))?
            .mask(NBytes::new(&mut exchange_private_key_bytes))?;

        let keypair = DIDKeyPair::try_from_private_key_bytes(KeyType::Ed25519, &private_key_bytes)
            .map_err(|e| SpongosError::Context("Mask", Error::did("unmasking DID private key", e).to_string()))?;
        let xkeypair = DIDKeyPair::try_from_private_key_bytes(KeyType::X25519, &exchange_private_key_bytes)
            .map_err(|e| SpongosError::Context("Mask", Error::did("unmasking DID exchange private key", e).to_string()))?;
        *did.info_mut().keypair_mut() = keypair;
        *did.info_mut().exchange_keypair_mut() = xkeypair;

        Ok(self)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDInfo {
    url_info: DIDUrlInfo,
    keypair: KeyPair,
    exchange_keypair: KeyPair,
}

impl DIDInfo {
    pub fn new(url_info: DIDUrlInfo, keypair: DIDKeyPair, exchange_keypair: DIDKeyPair) -> Self {
        Self {
            url_info,
            keypair: KeyPair(keypair),
            exchange_keypair: KeyPair(exchange_keypair),
        }
    }

    pub fn url_info(&self) -> &DIDUrlInfo {
        &self.url_info
    }

    pub fn url_info_mut(&mut self) -> &mut DIDUrlInfo {
        &mut self.url_info
    }

    pub(crate) fn keypair(&self) -> &DIDKeyPair {
        &self.keypair.0
    }

    fn keypair_mut(&mut self) -> &mut DIDKeyPair {
        &mut self.keypair.0
    }

    fn exchange_keypair(&self) -> &DIDKeyPair {
        &self.exchange_keypair.0
    }

    fn exchange_keypair_mut(&mut self) -> &mut DIDKeyPair {
        &mut self.exchange_keypair.0
    }

    pub(crate) fn exchange_key(&self) -> Result<x25519::SecretKey> {
        x25519::SecretKey::try_from_slice(self.exchange_keypair.0.private().as_ref())
            .map_err(|e| Error::Crypto("exchange_key from kepair", e))
    }
}

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
