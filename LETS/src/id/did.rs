// Rust
use alloc::{
    string::{
        String,
        ToString,
    },
    vec::Vec,
};
use core::convert::TryInto;

// 3rd party
use anyhow::{
    anyhow,
    Result,
};
use serde::Serialize;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use identity::{
    core::{
        decode_b58,
        encode_b58,
    },
    crypto::{
        SetSignature,
        Signature,
        TrySignature,
        TrySignatureMut,
    },
    did::{
        MethodUriType,
        TryMethod,
        DID as IdentityDID,
    },
    iota::IotaDID,
};

// TODO: REMOVE
// use iota_streams_core::{
//     err,
//     prelude::{
//         generic_array::{
//             typenum::U32,
//             GenericArray,
//         },
//         String,
//         Vec,
//     },
//     Errors::DIDMissing,
//     Result,
// };

// type DIDSize = U32;
// type DIDWrap = GenericArray<u8, DIDSize>;
// type DIDClient = identity::iota::Client;

pub(crate) const DID_CORE: &str = "did:iota:";

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
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

pub enum DID {
    // TODO: Add DID Account implementation
    PrivateKey(DIDInfo),
}

impl DID {
    pub(crate) fn info(&self) -> &DIDInfo {
        match self {
            Self::PrivateKey(did_info) => did_info,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DIDInfo {
    did: IotaDID,
    key_fragment: String,
    keypair: identity::crypto::KeyPair,
}

impl DIDInfo {
    pub(crate) fn did(&self) -> &IotaDID {
        &self.did
    }

    pub(crate) fn method_id(&self) -> &str {
        self.did().method_id()
    }

    pub(crate) fn key_fragment(&self) -> &str {
        &self.key_fragment
    }

    pub(crate) fn keypair(&self) -> &identity::crypto::KeyPair {
        &self.keypair
    }

    pub(crate) fn sig_kp(&self) -> (ed25519::SecretKey, ed25519::PublicKey) {
        let mut key_bytes = [0_u8; ed25519::SECRET_KEY_LENGTH];
        key_bytes.clone_from_slice(self.keypair.private().as_ref());
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
