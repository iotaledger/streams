use anyhow::{
    bail,
    Result,
};

use super::Context;
use crate::{
    command::{
        Absorb,
        Commit,
        Mask,
        X25519,
    },
    io,
    types::NBytes,
};
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::key_exchange::x25519;

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::StaticSecret, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(&mut self, sk: &x25519::StaticSecret, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb(shared.as_bytes());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> X25519<x25519::EphemeralSecret, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(&mut self, sk: x25519::EphemeralSecret, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb(shared.as_bytes());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes> for Context<F, OS> {
    fn x25519(&mut self, pk: &x25519::PublicKey, key: &NBytes) -> Result<&mut Self> {
        // TODO: no_std make default rng
        #[cfg(feature = "std")]
        {
            let ephemeral_ke_sk = x25519::EphemeralSecret::new(&mut rand::thread_rng());
            let ephemeral_ke_pk = x25519::PublicKey::from(&ephemeral_ke_sk);
            self.absorb(&ephemeral_ke_pk)?
                .x25519(ephemeral_ke_sk, pk)?
                .commit()?
                .mask(key)
        }
        #[cfg(not(feature = "std"))]
        bail!("no_std default rng not implemented")
    }
}
