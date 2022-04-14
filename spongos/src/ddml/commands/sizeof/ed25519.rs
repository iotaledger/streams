use crypto::signatures::ed25519;
use anyhow::Result;
use generic_array::{typenum::U64, GenericArray};

use crate::ddml::{
    commands::{
        sizeof::Context,
        Ed25519,
    },
    modifiers::External,
    types::{
        Mac,
        NBytes,
    },
};

/// Signature size is 64 bytes
impl Ed25519<&ed25519::SecretKey, &External<NBytes<GenericArray<u8, U64>>>> for Context {
    fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: &External<NBytes<GenericArray<u8, U64>>>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

/// Signature size is 64 bytes
impl Ed25519<&ed25519::SecretKey, &External<NBytes<[u8; 64]>>> for Context {
    fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: &External<NBytes<[u8; 64]>>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

// TODO: REMOVE?
// /// Signature size is 64 bytes
// impl Ed25519<&ed25519::SecretKey, &External<Mac>> for Context {
//     fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: &External<Mac>) -> Result<&mut Self> {
//         self.size += ed25519::SIGNATURE_LENGTH;
//         Ok(self)
//     }
// }

// TODO: REMOVE
// impl Ed25519<&ed25519::SecretKey, HashSig> for Context {
//     fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: HashSig) -> Result<&mut Self> {
//         // Squeeze external and commit cost nothing in the stream.
//         self.size += ed25519::SIGNATURE_LENGTH;
//         Ok(self)
//     }
// }
