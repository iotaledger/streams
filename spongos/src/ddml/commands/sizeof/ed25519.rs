use crypto::signatures::ed25519;
use anyhow::Result;
use generic_array::typenum::U64;

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
impl<F> Ed25519<&ed25519::SecretKey, &External<NBytes<U64>>> for Context<F> {
    fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: &External<NBytes<U64>>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

/// Signature size is 64 bytes
impl<F> Ed25519<&ed25519::SecretKey, &External<Mac>> for Context<F> {
    fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: &External<Mac>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

// TODO: REMOVE
// impl<F> Ed25519<&ed25519::SecretKey, HashSig> for Context<F> {
//     fn ed25519(&mut self, _sk: &ed25519::SecretKey, _hash: HashSig) -> Result<&mut Self> {
//         // Squeeze external and commit cost nothing in the stream.
//         self.size += ed25519::SIGNATURE_LENGTH;
//         Ok(self)
//     }
// }
