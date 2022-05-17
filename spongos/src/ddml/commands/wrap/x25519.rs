use anyhow::Result;
use crypto::keys::x25519;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::Context,
            Absorb,
            Commit,
            Mask,
            X25519,
        },
        io,
        modifiers::External,
        types::NBytes,
    },
};

#[cfg(feature = "osrng")]
use rand::{
    rngs::StdRng,
    SeedableRng,
};
// X25519 wrap command requires randomly generating an x25519 keypair. Because of that, it can only be compiled
// on architectures supported by `getrandom`.
#[cfg(feature = "osrng")]
impl<'a, F: PRP, T: AsRef<[u8]>, OS: io::OStream> X25519<&'a x25519::PublicKey, NBytes<T>> for Context<OS, F> {
    fn x25519(&mut self, remote_public_key: &x25519::PublicKey, key: NBytes<T>) -> Result<&mut Self> {
        let ephemeral_secret_key = x25519::SecretKey::generate_with(&mut StdRng::from_entropy());
        let shared_secret = ephemeral_secret_key.diffie_hellman(remote_public_key);
        self.absorb(&ephemeral_secret_key.public_key())?
            .absorb(External::new(&NBytes::new(shared_secret.as_bytes())))?
            .commit()?
            .mask(key)
    }
}
