use crypto::keys::x25519;

// TODO: REMOVE
// #[cfg(feature = "std")]
// use iota_streams_core::prng::rng;
// #[cfg(not(feature = "std"))]
// use iota_streams_core::{
//     err,
//     Errors::NoStdRngMissing,
// };
// #[cfg(feature = "std")]
// use crate::command::{
//     Absorb,
//     Commit,
//     Mask,
// };
use anyhow::Result;
use generic_array::ArrayLength;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
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
        types::{
            Bytes,
            Mac,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
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
impl<'a, F: PRP, T: AsRef<[u8]>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<T>> for Context<F, OS> {
    fn x25519(&mut self, remote_public_key: &x25519::PublicKey, key: &NBytes<T>) -> Result<&mut Self> {
        let ephemeral_secret_key = x25519::SecretKey::generate_with(&mut StdRng::from_entropy());
        let shared_secret = ephemeral_secret_key.diffie_hellman(remote_public_key);
        self.absorb(&ephemeral_secret_key.public_key())?
            .absorb(External::new(NBytes::new(shared_secret.as_bytes())))?
            .commit()?
            .mask(key)
    }
}

// #[cfg(not(feature = "std"))]
// impl<'a, F, N: ArrayLength<u8>, OS> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
//     fn x25519(&mut self, _pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
//         // TODO: no_std make default rng
//         err!(NoStdRngMissing)
//     }
// }
