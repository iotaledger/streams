use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use generic_array::ArrayLength;
use anyhow::Result;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Mask,
    },
    types::{
        Bytes,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

/// Mask Uint8.
impl<F> Mask<Uint8> for Context<F> {
    fn mask(&mut self, _val: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Mask Uint16.
impl<F> Mask<Uint16> for Context<F> {
    fn mask(&mut self, _val: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Mask Uint32.
impl<F> Mask<Uint32> for Context<F> {
    fn mask(&mut self, _val: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Mask Uint64.
impl<F> Mask<Uint64> for Context<F> {
    fn mask(&mut self, _val: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Mask Size.
impl<F> Mask<Size> for Context<F> {
    fn mask(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
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
        let size = Size::new(bytes.len());
        self.mask(size)?;
        self.size += bytes.len();
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
