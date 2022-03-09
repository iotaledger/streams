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
use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            wrap::Context,
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

impl<'a, F: PRP, OS> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F, OS> {
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

// TODO: REMOVE
// #[cfg(feature = "std")]
// impl<'a, F, N: ArrayLength<u8>, OS> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
//     fn x25519(&mut self, remote_public_key: &x25519::PublicKey, key: &NBytes<N>) -> Result<&mut Self> {
//         let ephemeral_secret_key = x25519::SecretKey::generate_with(&mut rng());
//         self.absorb(&ephemeral_secret_key.public_key())?
//             .x25519(&ephemeral_secret_key, remote_public_key)?
//             .commit()?
//             .mask(key)
//     }
// }

// #[cfg(not(feature = "std"))]
// impl<'a, F, N: ArrayLength<u8>, OS> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
//     fn x25519(&mut self, _pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
//         // TODO: no_std make default rng
//         err!(NoStdRngMissing)
//     }
// }
