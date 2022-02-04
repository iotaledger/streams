use crypto::keys::x25519;

#[cfg(not(feature = "std"))]
use iota_streams_core::{
    err,
    Errors::NoStdRngMissing,
};

use iota_streams_core::{
    sponge::prp::PRP,
    Result,
};

use super::Context;
#[cfg(feature = "std")]
use crate::command::{
    Absorb,
    Commit,
    Mask,
};
use crate::{
    command::X25519,
    io,
    types::{
        ArrayLength,
        NBytes,
    },
};

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(
        &mut self,
        local_secret_key: &x25519::SecretKey,
        remote_public_key: &x25519::PublicKey,
    ) -> Result<&mut Self> {
        let shared_secret = local_secret_key.diffie_hellman(remote_public_key);
        self.spongos.absorb(shared_secret.as_bytes());
        Ok(self)
    }
}

#[cfg(feature = "std")]
impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
    fn x25519(&mut self, remote_public_key: &x25519::PublicKey, key: &NBytes<N>) -> Result<&mut Self> {
        let ephemeral_secret_key = x25519::SecretKey::generate_with(&mut rand::thread_rng());
        self.absorb(&ephemeral_secret_key.public_key())?
            .x25519(&ephemeral_secret_key, remote_public_key)?
            .commit()?
            .mask(key)
    }
}

#[cfg(not(feature = "std"))]
impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
    fn x25519(&mut self, _pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
        // TODO: no_std make default rng
        err!(NoStdRngMissing)
    }
}
