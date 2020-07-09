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

/// Recover public key.
impl<'a, F, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes>>
    for Context<F, IS>
where
    F: PRP,
{
    fn ed25519(&mut self, _pk: &'a ed25519::PublicKey, _hash: &'a External<NBytes>) -> Result<&mut Self> {
        let _sig = self.stream.try_advance(64)?;
        //TODO: pk.verify_prehashed(hash, None, sig)?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, HashSig> for Context<F, IS>
where
    F: PRP,
{
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, _hash: HashSig) -> Result<&mut Self> {
        let mut hash = External(NBytes(vec![0; 64]));
        self
            .squeeze(&mut hash)?
            .commit()?
            .ed25519(pk, &hash)
    }
}
