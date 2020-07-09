use anyhow::{
    Result,
};

use super::Context;
use crate::{
    command::{
        Commit,
        Ed25519,
        Squeeze,
    },
    io,
    types::{
        External,
        HashSig,
        NBytes,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
};
use iota_streams_core_edsig::signature::ed25519;

/// Signature size depends on Merkle tree height.
impl<F, OS: io::OStream> Ed25519<&ed25519::Keypair, &External<NBytes>> for Context<F, OS>
where
    F: PRP,
{
    fn ed25519(&mut self, sk: &ed25519::Keypair, hash: &External<NBytes>) -> Result<&mut Self> {
        self.stream
            .try_advance(64)?
            .copy_from_slice(&sk.sign(&((hash.0).0)[..]).to_bytes());
        //TODO: sign_prehashed
        Ok(self)
    }
}

impl<F, OS: io::OStream> Ed25519<&ed25519::Keypair, HashSig> for Context<F, OS>
where
    F: PRP,
{
    fn ed25519(&mut self, sk: &ed25519::Keypair, _hash: HashSig) -> Result<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        let mut hash = External(NBytes(vec![0; 64]));
        self
            .squeeze(&mut hash)?
            .commit()?
            .ed25519(sk, &hash)
    }
}
