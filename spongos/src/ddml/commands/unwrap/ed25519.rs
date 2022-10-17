use core::convert::TryInto;
use crypto::signatures::ed25519;

use crate::{
    ddml::{
        commands::{unwrap::Context, Ed25519},
        io,
        modifiers::External,
        types::NBytes,
    },
    error::{Error, Result},
};

/// Uses the provided Ed25519 Public Key to verify a signature hash.
impl<'a, F, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, External<&'a NBytes<[u8; 64]>>> for Context<IS, F> {
    fn ed25519(
        &mut self,
        public_key: &'a ed25519::PublicKey,
        hash: External<&'a NBytes<[u8; 64]>>,
    ) -> Result<&mut Self> {
        let signature_bytes = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        self.cursor += ed25519::SIGNATURE_LENGTH;
        let signature = ed25519::Signature::from_bytes(signature_bytes.try_into()?);
        let is_valid = public_key.verify(&signature, hash.inner().as_slice());

        match is_valid {
            true => Ok(self),
            false => Err(Error::SignatureMismatch),
        }
    }
}
