use anyhow::Result;
use crypto::keys::x25519;
use generic_array::ArrayLength;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{
                Context,
                Unwrap,
            },
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
    error::Error::BadMac,
};

impl<'a, F: PRP, T: AsMut<[u8]>, IS: io::IStream> X25519<&'a x25519::SecretKey, &'a mut NBytes<T>> for Context<F, IS> {
    fn x25519(&mut self, secret_key: &x25519::SecretKey, encryption_key: &mut NBytes<T>) -> Result<&mut Self> {
        let mut ephemeral_public_key = x25519::PublicKey::from([0u8; x25519::PUBLIC_KEY_LENGTH]);
        self.absorb(&mut ephemeral_public_key)?;
        let shared_key = secret_key.diffie_hellman(&ephemeral_public_key);
        self.absorb(External::new(&NBytes::new(shared_key.as_bytes())))?
            .commit()?
            .mask(encryption_key)?;
        Ok(self)
    }
}
