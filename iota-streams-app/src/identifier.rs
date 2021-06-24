use iota_streams_core::{
    err,
    Errors::IdentifierGenerationFailure,
    prelude::{
        digest::generic_array::GenericArray,
        Vec,
    },
    psk::{
        Psk,
        PskId,
        PSKID_SIZE,
    }
};

use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKeyWrap),
    XPubKey(x25519::PublicKeyWrap),
    PskId(PskId),
    Psk(Psk),
}

impl Identifier {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Identifier::XPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::EdPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::PskId(id) => id.to_vec(),
            Identifier::Psk(id) => id.to_vec()
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> iota_streams_core::Result<Self> {
        match bytes.len() {
            ed25519::PUBLIC_KEY_LENGTH => Ok(Identifier::EdPubKey(ed25519::PublicKey::from_bytes(bytes)?.into())),
            PSKID_SIZE => Ok(Identifier::PskId(GenericArray::clone_from_slice(bytes))),
            _ => err(IdentifierGenerationFailure)
        }
    }

    pub fn get_pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self { Some(&pk.0) } else { None }
    }

    pub fn get_xpk(&self) -> Option<&x25519::PublicKey> {
        if let Identifier::XPubKey(xpk) = self { Some(&xpk.0) } else { None }
    }

    pub fn get_psk(&self) -> Option<&Psk> {
        if let Identifier::Psk(psk) = self { Some(psk) } else { None }
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk.into())
    }
}

impl From<&PskId> for Identifier {
    fn from(pskid: &PskId) -> Self {
        Identifier::PskId((*pskid).into())
    }
}

impl From<&Psk> for Identifier {
    fn from(psk: &Psk) -> Self {
        Identifier::Psk((*psk).into())
    }
}
