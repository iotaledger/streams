// Rust
use alloc::{
    string::String,
    vec::Vec,
};
use core::hash::Hash;

// 3rd-party
use anyhow::{anyhow, Result};
use serde::Serialize;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};
use identity_iota::{
    crypto::{SetSignature, Proof, GetSignature, GetSignatureMut, KeyType, KeyPair as DIDKeyPair},
    did::{MethodUriType, TryMethod, DID as IdentityDID},
    iota_core::IotaDID,
};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::{Bytes, NBytes},
    },
    PRP,
};

#[derive(Serialize)]
pub(crate) struct DataWrapper<'a> {
    data: &'a [u8],
    signature: Option<Proof>,
}

impl<'a> DataWrapper<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, signature: None }
    }

    pub(crate) fn with_signature(mut self, signature: Proof) -> Self {
        self.signature = Some(signature);
        self
    }

    pub(crate) fn into_signature(self) -> Option<Proof> {
        self.signature
    }
}

impl<'a> GetSignature for DataWrapper<'a> {
    fn signature(&self) -> Option<&Proof> {
        self.signature.as_ref()
    }
}

impl<'a> GetSignatureMut for DataWrapper<'a> {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.signature.as_mut()
    }
}

impl<'a> SetSignature for DataWrapper<'a> {
    fn set_signature(&mut self, signature: Proof) {
        self.signature = Some(signature)
    }
}

impl<'a> TryMethod for DataWrapper<'a> {
    const TYPE: MethodUriType = MethodUriType::Absolute;
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDInfo {
    url_info: DIDUrlInfo,
    keypair: KeyPair,
    exchange_keypair: KeyPair,
}

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDUrlInfo {
    did: String,
    client_url: String,
    exchange_fragment: String,
    signing_fragment: String,
}

impl DIDInfo {
    pub fn new(url_info: DIDUrlInfo, keypair: DIDKeyPair, exchange_keypair: DIDKeyPair) -> Self {
        Self {
            url_info,
            keypair: KeyPair(keypair),
            exchange_keypair: KeyPair(exchange_keypair)
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
            .map_err(|e| e.into())
    }

    pub(crate) fn sig_kp(&self) -> (ed25519::SecretKey, ed25519::PublicKey) {
        let mut key_bytes = [0u8; ed25519::SECRET_KEY_LENGTH];
        key_bytes.clone_from_slice(self.keypair().private().as_ref());
        let signing_secret_key = ed25519::SecretKey::from_bytes(key_bytes);
        let signing_public_key = signing_secret_key.public_key();
        (signing_secret_key, signing_public_key)
    }

    pub(crate) fn ke_kp(&self) -> (x25519::SecretKey, x25519::PublicKey) {
        let kp = self.sig_kp();
        let key_exchange_secret_key = x25519::SecretKey::from(&kp.0);
        let key_exchange_public_key = key_exchange_secret_key.public_key();
        (key_exchange_secret_key, key_exchange_public_key)
    }
}

impl DIDUrlInfo {
    pub fn new<T: Into<String>>(did: IotaDID, client_url: T, exchange_fragment: T, signing_fragment: T) -> Self {
        Self {
            did: did.into_string(),
            client_url: client_url.into(),
            exchange_fragment: exchange_fragment.into(),
            signing_fragment: signing_fragment.into(),
        }
    }

    pub(crate) fn did(&self) -> &str {
        &self.did
    }

    pub(crate) fn client_url(&self) -> &str {
        &self.client_url
    }

    pub(crate) fn exchange_fragment(&self) -> &str {
        &self.exchange_fragment
    }

    pub(crate) fn signing_fragment(&self) -> &str {
        &self.signing_fragment
    }

    pub(crate) fn did_mut(&mut self) -> &mut String {
        &mut self.did
    }

    pub(crate) fn client_url_mut(&mut self) -> &mut String {
        &mut self.client_url
    }

    pub(crate) fn exchange_fragment_mut(&mut self) -> &mut String {
        &mut self.exchange_fragment
    }

    pub(crate) fn signing_fragment_mut(&mut self) -> &mut String {
        &mut self.signing_fragment
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

        let keypair = identity_iota::crypto::KeyPair::try_from_private_key_bytes(KeyType::Ed25519, &private_key_bytes)
            .map_err(|e| anyhow!("error unmasking DID private key: {}", e))?;
        let xkeypair = identity_iota::crypto::KeyPair::try_from_private_key_bytes(KeyType::X25519, &exchange_private_key_bytes)
            .map_err(|e| anyhow!("error unmasking DID exchange private key: {}", e))?;
        *did.info_mut().keypair_mut() = keypair;
        *did.info_mut().exchange_keypair_mut() = xkeypair;

        Ok(self)
    }
}



impl Mask<&DIDUrlInfo> for sizeof::Context {
    fn mask(&mut self, url_info: &DIDUrlInfo) -> Result<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<OS, F> Mask<&DIDUrlInfo> for wrap::Context<OS, F>
    where
        F: PRP,
        OS: io::OStream,
{
    fn mask(&mut self, url_info: &DIDUrlInfo) -> Result<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<IS, F> Mask<&mut DIDUrlInfo> for unwrap::Context<IS, F>
    where
        F: PRP,
        IS: io::IStream,
{
    fn mask(&mut self, url_info: &mut DIDUrlInfo) -> Result<&mut Self> {
        let mut did_bytes = Vec::new();
        let mut client_url = Vec::new();
        let mut exchange_fragment_bytes = Vec::new();
        let mut signing_fragment_bytes = Vec::new();
        self.mask(Bytes::new(&mut did_bytes))?
            .mask(Bytes::new(&mut client_url))?
            .mask(Bytes::new(&mut exchange_fragment_bytes))?
            .mask(Bytes::new(&mut signing_fragment_bytes))?;

        *url_info.did_mut() = String::from_utf8(did_bytes)?;
        *url_info.client_url_mut() = String::from_utf8(client_url)?;
        *url_info.exchange_fragment_mut() = String::from_utf8(exchange_fragment_bytes)?;
        *url_info.signing_fragment_mut() = String::from_utf8(signing_fragment_bytes)?;
        Ok(self)
    }
}