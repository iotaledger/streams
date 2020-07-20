use anyhow::Result;

use super::Context;
use crate::{
    command::Ed25519,
    types::{
        External,
        HashSig,
        Mac,
        NBytes,
    },
};
use iota_streams_core_edsig::signature::ed25519;

/// Signature size depends on Merkle tree height.
impl<F> Ed25519<&ed25519::Keypair, &External<NBytes>> for Context<F> {
    fn ed25519(&mut self, _sk: &ed25519::Keypair, _hash: &External<NBytes>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

impl<F> Ed25519<&ed25519::Keypair, &External<Mac>> for Context<F> {
    fn ed25519(&mut self, _sk: &ed25519::Keypair, _hash: &External<Mac>) -> Result<&mut Self> {
        self.size += ed25519::SIGNATURE_LENGTH;
        Ok(self)
    }
}

impl<F> Ed25519<&ed25519::Keypair, HashSig> for Context<F> {
    fn ed25519(&mut self, _sk: &ed25519::Keypair, _hash: HashSig) -> Result<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        self.size += 64;
        Ok(self)
    }
}
