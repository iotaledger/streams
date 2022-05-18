// Rust
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    convert::TryInto,
    fmt::{LowerHex, UpperHex},
    hash::Hash,
};

// 3rd-party
use anyhow::{anyhow, Result};
use serde::Serialize;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};
use identity::{
    core::{decode_b58, encode_b58},
    crypto::{SetSignature, Signature, TrySignature, TrySignatureMut},
    did::{MethodUriType, TryMethod, DID as IdentityDID},
    iota::IotaDID,
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

pub(crate) const DID_CORE: &str = "did:iota:";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct DIDMethodId([u8; 32]);

impl DIDMethodId {
    pub(crate) fn new(method_id_bytes: [u8; 32]) -> Self {
        Self(method_id_bytes)
    }

    pub(crate) fn from_did_unsafe(did: &IotaDID) -> Self {
        Self::new(
            decode_b58(did.method_id())
                .expect("decoding DID method-id")
                .try_into()
                .expect("DID method-id vector should fit into a 32 Byte array"),
        )
    }

    pub(crate) fn try_to_did(&self) -> Result<IotaDID> {
        let did_str = DID_CORE.to_string() + &encode_b58(self);
        Ok(IotaDID::parse(did_str)?)
    }
}

impl AsRef<[u8]> for DIDMethodId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for DIDMethodId {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl LowerHex for DIDMethodId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

impl UpperHex for DIDMethodId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode_upper(self))
    }
}

#[derive(Serialize)]
pub(crate) struct DataWrapper<'a> {
    data: &'a [u8],
    signature: Option<Signature>,
}

impl<'a> DataWrapper<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, signature: None }
    }

    pub(crate) fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = Some(signature);
        self
    }

    pub(crate) fn into_signature(self) -> Option<Signature> {
        self.signature
    }
}

impl<'a> TrySignature for DataWrapper<'a> {
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

impl<'a> TrySignatureMut for DataWrapper<'a> {
    fn signature_mut(&mut self) -> Option<&mut Signature> {
        self.signature.as_mut()
    }
}

impl<'a> SetSignature for DataWrapper<'a> {
    fn set_signature(&mut self, signature: Signature) {
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
    did: IotaDID,
    key_fragment: String,
    keypair: KeyPair,
}

impl DIDInfo {
    pub fn new(did: IotaDID, key_fragment: String, keypair: identity::crypto::KeyPair) -> Self {
        Self {
            did,
            key_fragment,
            keypair: KeyPair(keypair),
        }
    }
    pub(crate) fn did(&self) -> &IotaDID {
        &self.did
    }

    pub(crate) fn key_fragment(&self) -> &str {
        &self.key_fragment
    }

    pub(crate) fn keypair(&self) -> &identity::crypto::KeyPair {
        &self.keypair.0
    }

    fn did_mut(&mut self) -> &mut IotaDID {
        &mut self.did
    }

    fn key_fragment_mut(&mut self) -> &mut String {
        &mut self.key_fragment
    }

    fn keypair_mut(&mut self) -> &mut identity::crypto::KeyPair {
        &mut self.keypair.0
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

struct KeyPair(identity::crypto::KeyPair);

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
        self.mask(Bytes::new(did.info().did().as_str()))?
            .mask(Bytes::new(did.info().key_fragment()))?
            .mask(NBytes::new(did.info().keypair().private()))
    }
}

impl<OS, F> Mask<&DID> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, did: &DID) -> Result<&mut Self> {
        self.mask(Bytes::new(did.info().did().as_str()))?
            .mask(Bytes::new(did.info().key_fragment()))?
            .mask(NBytes::new(did.info().keypair().private()))
    }
}

impl<IS, F> Mask<&mut DID> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, did: &mut DID) -> Result<&mut Self> {
        let mut did_bytes = Vec::new();
        let mut fragment_bytes = Vec::new();
        let mut private_key_bytes = [0; ed25519::SECRET_KEY_LENGTH];
        self.mask(Bytes::new(&mut did_bytes))?
            .mask(Bytes::new(&mut fragment_bytes))?
            .mask(NBytes::new(&mut private_key_bytes))?;

        *did.info_mut().did_mut() = core::str::from_utf8(&did_bytes)?.try_into()?;
        *did.info_mut().key_fragment_mut() = String::from_utf8(fragment_bytes)?;

        let keypair = identity::crypto::KeyPair::try_from_ed25519_bytes(&private_key_bytes)
            .map_err(|e| anyhow!("error unmasking DID private key: {}", e))?;
        *did.info_mut().keypair_mut() = keypair;

        Ok(self)
    }
}
