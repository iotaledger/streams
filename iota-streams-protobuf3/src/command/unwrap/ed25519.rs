use anyhow::{
    bail,
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
        Prehashed,
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
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, hash: &'a External<NBytes>) -> Result<&mut Self> {
        let context = "IOTAStreams".as_bytes();
        let mut prehashed = Prehashed::default();
        prehashed.0.as_mut_slice().copy_from_slice(&(hash.0).0[..]);
        let mut bytes = [0_u8; ed25519::SIGNATURE_LENGTH];
        let slice = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        bytes.copy_from_slice(slice);
        let signature = ed25519::Signature::new(bytes);
        match pk.verify_prehashed(prehashed, Some(context), &signature) {
                Ok(()) => Ok(self),
                Err(err) => bail!("bad signature: {}", err),
        }
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
