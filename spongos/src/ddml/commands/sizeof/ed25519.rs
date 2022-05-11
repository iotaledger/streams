use anyhow::Result;
use crypto::signatures::ed25519;
use generic_array::{
    typenum::U64,
    GenericArray,
};

use crate::ddml::{
    commands::{
        sizeof::Context,
        Ed25519,
    },
    modifiers::External,
    types::NBytes,
};

/// Signature size is 64 bytes
impl Ed25519<&ed25519::SecretKey, &External<NBytes<GenericArray<u8, U64>>>> for Context {
    fn ed25519(
        &mut self,
        _sk: &ed25519::SecretKey,
        _hash: &External<NBytes<GenericArray<u8, U64>>>,
    ) -> Result<&mut Self> {
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
