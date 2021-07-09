use iota_streams_core::Result;

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
        U64,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    wrapped_err,
    Errors::SignatureFailure,
    WrappedError,
};
use iota_streams_core_edsig::signature::ed25519;

/// Signature size depends on Merkle tree height.
impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::Keypair, &External<NBytes<U64>>> for Context<F, OS> {
    fn ed25519(&mut self, kp: &ed25519::Keypair, hash: &External<NBytes<U64>>) -> Result<&mut Self> {
        let context = "IOTAStreams".as_bytes();
        let mut prehashed = Prehashed::default();
        prehashed.0.as_mut_slice().copy_from_slice((hash.0).as_slice());
        match kp.sign_prehashed(prehashed, Some(&context[..])) {
            Ok(signature) => {
                self.stream
                    .try_advance(ed25519::SIGNATURE_LENGTH)?
                    .copy_from_slice(&signature.to_bytes());
                Ok(self)
            }
            Err(e) => Err(wrapped_err!(SignatureFailure, WrappedError(e))),
        }
    }
}

impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::Keypair, HashSig> for Context<F, OS> {
    fn ed25519(&mut self, sk: &ed25519::Keypair, _hash: HashSig) -> Result<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(sk, &hash)
    }
}
