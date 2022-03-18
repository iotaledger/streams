use crypto::signatures::ed25519;

use iota_streams_core::{
    sponge::prp::PRP,
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
        U64,
    },
};

impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::SecretKey, &External<NBytes<U64>>> for Context<F, OS> {
    fn ed25519(&mut self, secret_key: &ed25519::SecretKey, hash: &External<NBytes<U64>>) -> Result<&mut Self> {
        let signature = secret_key.sign(hash.0.as_slice());
        self.stream
            .try_advance(ed25519::SIGNATURE_LENGTH)?
            .copy_from_slice(&signature.to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::SecretKey, HashSig> for Context<F, OS> {
    fn ed25519(&mut self, sk: &ed25519::SecretKey, _hash: HashSig) -> Result<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(sk, &hash)
    }
}
