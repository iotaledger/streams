use core::convert::TryInto;

use anyhow::{
    ensure,
    Result,
};
use crypto::signatures::ed25519;
use generic_array::{
    typenum::U64,
    GenericArray,
};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::Context,
            Commit,
            Ed25519,
            Squeeze,
        },
        io,
        modifiers::External,
        types::NBytes,
    },
    error::Error::SignatureMismatch,
};

/// Recover public key.
impl<'a, F, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes<GenericArray<u8, U64>>>>
    for Context<F, IS>
{
    fn ed25519(
        &mut self,
        public_key: &'a ed25519::PublicKey,
        hash: &'a External<NBytes<GenericArray<u8, U64>>>,
    ) -> Result<&mut Self> {
        let signature_bytes = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        self.cursor += ed25519::SIGNATURE_LENGTH;
        let signature = ed25519::Signature::from_bytes(signature_bytes.try_into()?);
        let is_valid = public_key.verify(&signature, hash.inner().as_slice());
        ensure!(is_valid, SignatureMismatch);
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes<[u8; 64]>>> for Context<F, IS> {
    fn ed25519(
        &mut self,
        public_key: &'a ed25519::PublicKey,
        hash: &'a External<NBytes<[u8; 64]>>,
    ) -> Result<&mut Self> {
        let signature_bytes = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        self.cursor += ed25519::SIGNATURE_LENGTH;
        let signature = ed25519::Signature::from_bytes(signature_bytes.try_into()?);
        let is_valid = public_key.verify(&signature, hash.inner().as_slice());
        ensure!(is_valid, SignatureMismatch);
        Ok(self)
    }
}
