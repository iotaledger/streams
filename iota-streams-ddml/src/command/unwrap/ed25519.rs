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
    Errors::SignatureMismatch,
    WrappedError,
};
use iota_streams_core_edsig::signature::ed25519;

/// Recover public key.
impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes<U64>>> for Context<F, IS> {
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, hash: &'a External<NBytes<U64>>) -> Result<&mut Self> {
        let context = "IOTAStreams".as_bytes();
        let mut prehashed = Prehashed::default();
        prehashed.0.as_mut_slice().copy_from_slice((hash.0).as_slice());
        let mut bytes = [0_u8; ed25519::SIGNATURE_LENGTH];
        let slice = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        bytes.copy_from_slice(slice);
        let signature = ed25519::Signature::new(bytes);
        match pk.verify_prehashed(prehashed, Some(context), &signature) {
            Ok(()) => Ok(self),
            Err(e) => Err(wrapped_err!(SignatureMismatch, WrappedError(e))),
        }
    }
}

impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, HashSig> for Context<F, IS> {
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, _hash: HashSig) -> Result<&mut Self> {
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(pk, &hash)
    }
}
