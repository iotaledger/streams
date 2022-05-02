use identity::{
    crypto::{
        SetSignature,
        Proof,
        GetSignature,
        GetSignatureMut,
    },
    did::{
        MethodUriType,
        TryMethod,
    },
    iota_core::IotaDID,
};

use iota_streams_core::{
    err,
    prelude::{
        generic_array::{
            typenum::U32,
            GenericArray,
        },
        String,
        Vec,
    },
    Errors::DIDMissing,
    Result,
};

use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use serde::Serialize;

pub type DIDSize = U32;
pub type DIDWrap = GenericArray<u8, DIDSize>;
pub type DIDClient = identity::iota::Client;

pub const DID_CORE: &str = "did:iota:";

#[derive(Serialize)]
pub struct DataWrapper {
    pub data: Vec<u8>,
    pub signature: Option<Proof>,
}

impl GetSignature for DataWrapper {
    fn signature(&self) -> Option<&Proof> {
        self.signature.as_ref()
    }
}

impl GetSignatureMut for DataWrapper {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.signature.as_mut()
    }
}

impl SetSignature for DataWrapper {
    fn set_signature(&mut self, signature: Proof) {
        self.signature = Some(signature)
    }
}

impl TryMethod for DataWrapper {
    const TYPE: MethodUriType = MethodUriType::Absolute;
}

pub struct DIDInfo {
    pub did: Option<IotaDID>,
    pub key_fragment: String,
    pub did_keypair: identity::crypto::KeyPair,
}

pub enum DIDImpl {
    // TODO: Add DID Account implementation
    PrivateKey(DIDInfo),
}

impl DIDInfo {
    pub fn did(&self) -> Result<IotaDID> {
        match &self.did {
            Some(did) => Ok(did.clone()),
            None => err(DIDMissing),
        }
    }

    pub fn sig_kp(&self) -> (ed25519::SecretKey, ed25519::PublicKey) {
        let mut key_bytes = [0_u8; ed25519::SECRET_KEY_LENGTH];
        key_bytes.clone_from_slice(self.did_keypair.private().as_ref());
        let signing_secret_key = ed25519::SecretKey::from_bytes(key_bytes);
        let signing_public_key = signing_secret_key.public_key();
        (signing_secret_key, signing_public_key)
    }

    pub fn ke_kp(&self) -> (x25519::SecretKey, x25519::PublicKey) {
        let kp = self.sig_kp();
        let key_exchange_secret_key = x25519::SecretKey::from(&kp.0);
        let key_exchange_public_key = key_exchange_secret_key.public_key();
        (key_exchange_secret_key, key_exchange_public_key)
    }
}
