use crypto::signatures::ed25519;

use crate::{
    ddml::{
        commands::{wrap::Context, Ed25519},
        io,
        modifiers::External,
        types::NBytes,
    },
    error::Result,
};

/// Uses the provided Ed25519 Secret Key to sign a hash. The signature is then absorbed into
/// [`Context`].
impl<F, OS: io::OStream> Ed25519<&ed25519::SecretKey, External<&NBytes<[u8; 64]>>> for Context<OS, F> {
    fn ed25519(&mut self, secret_key: &ed25519::SecretKey, hash: External<&NBytes<[u8; 64]>>) -> Result<&mut Self> {
        let signature = secret_key.sign(hash.inner().as_slice());
        self.stream
            .try_advance(ed25519::SIGNATURE_LENGTH)?
            .copy_from_slice(&signature.to_bytes());
        Ok(self)
    }
}
