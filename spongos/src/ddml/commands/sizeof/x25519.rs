use crypto::keys::x25519;
use anyhow::Result;
use generic_array::ArrayLength;

use crate::ddml::{
    commands::{
        sizeof::Context,
        X25519,
    },
    types::NBytes,
};

impl<'a, F> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F> {
    fn x25519(&mut self, _sk: &x25519::SecretKey, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        // Only shared secret is absorbed externally.
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F, N: ArrayLength<u8>> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F> {
//     fn x25519(&mut self, _pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
//         self.size += 32 + N::USIZE;
//         Ok(self)
//     }
// }
