use crypto::keys::x25519;
use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{
                Context,
                Unwrap,
            },
            X25519,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Mac,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
    error::Error::BadMac,
};

impl<'a, F: PRP, IS> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F, IS> {
    fn x25519(&mut self, sk: &x25519::SecretKey, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb(shared.as_bytes());
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> X25519<&'a x25519::SecretKey, &'a mut NBytes<N>>
//     for Context<F, IS>
// {
//     fn x25519(&mut self, sk: &x25519::SecretKey, key: &mut NBytes<N>) -> Result<&mut Self> {
//         let mut ephemeral_ke_pk = x25519::PublicKey::from([0_u8; 32]);
//         (*self)
//             .absorb(&mut ephemeral_ke_pk)?
//             .x25519(sk, &ephemeral_ke_pk)?
//             .commit()?
//             .mask(key)
//     }
// }
