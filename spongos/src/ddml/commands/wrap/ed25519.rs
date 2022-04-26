use anyhow::Result;
use crypto::signatures::ed25519;
use generic_array::{
    typenum::U64,
    GenericArray,
};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Ed25519,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

impl<F, OS: io::OStream> Ed25519<&ed25519::SecretKey, &External<NBytes<GenericArray<u8, U64>>>> for Context<F, OS> {
    fn ed25519(
        &mut self,
        secret_key: &ed25519::SecretKey,
        hash: &External<NBytes<GenericArray<u8, U64>>>,
    ) -> Result<&mut Self> {
        let signature = secret_key.sign(hash.inner().as_slice());
        self.stream
            .try_advance(ed25519::SIGNATURE_LENGTH)?
            .copy_from_slice(&signature.to_bytes());
        Ok(self)
    }
}

impl<F, OS: io::OStream> Ed25519<&ed25519::SecretKey, &External<NBytes<[u8; 64]>>> for Context<F, OS> {
    fn ed25519(&mut self, secret_key: &ed25519::SecretKey, hash: &External<NBytes<[u8; 64]>>) -> Result<&mut Self> {
        let signature = secret_key.sign(hash.inner().as_slice());
        self.stream
            .try_advance(ed25519::SIGNATURE_LENGTH)?
            .copy_from_slice(&signature.to_bytes());
        Ok(self)
    }
}
