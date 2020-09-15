use anyhow::Result;

use super::Context;
use crate::{
    command::Mask,
    types::{
        sizeof_sizet,
        Bytes,
        NBytes,
        ArrayLength,
        Size,
        Uint8,
    },
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

/// Mask Uint8.
impl<F> Mask<&Uint8> for Context<F> {
    fn mask(&mut self, _val: &Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Mask Uint8.
impl<F> Mask<Uint8> for Context<F> {
    fn mask(&mut self, val: Uint8) -> Result<&mut Self> {
        self.mask(&val)
    }
}

/// Mask Size.
impl<F> Mask<&Size> for Context<F> {
    fn mask(&mut self, val: &Size) -> Result<&mut Self> {
        self.size += sizeof_sizet(val.0);
        Ok(self)
    }
}

/// Mask Size.
impl<F> Mask<Size> for Context<F> {
    fn mask(&mut self, val: Size) -> Result<&mut Self> {
        self.mask(&val)
    }
}

/// Mask `n` bytes.
impl<F, N: ArrayLength<u8>> Mask<&NBytes<N>> for Context<F> {
    fn mask(&mut self, _val: &NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

/// Mask bytes, the size prefixed before the content bytes is also masked.
impl<F> Mask<&Bytes> for Context<F> {
    fn mask(&mut self, bytes: &Bytes) -> Result<&mut Self> {
        let size = Size((bytes.0).len());
        self.mask(&size)?;
        self.size += (bytes.0).len();
        Ok(self)
    }
}

impl<F> Mask<&x25519::PublicKey> for Context<F> {
    fn mask(&mut self, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

impl<F> Mask<&ed25519::PublicKey> for Context<F> {
    fn mask(&mut self, _pk: &ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}
