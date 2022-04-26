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
impl Mask<Uint8> for Context {
    fn mask(&mut self, _val: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Mask Uint16.
impl Mask<Uint16> for Context {
    fn mask(&mut self, _val: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Mask Uint32.
impl Mask<Uint32> for Context {
    fn mask(&mut self, _val: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Mask Uint64.
impl Mask<Uint64> for Context {
    fn mask(&mut self, _val: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Mask Size.
impl Mask<Size> for Context {
    fn mask(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// Mask `n` bytes.
impl<T: AsRef<[u8]>> Mask<NBytes<&T>> for Context {
    fn mask(&mut self, nbytes: NBytes<&T>) -> Result<&mut Self> {
        self.size += nbytes.as_ref().len();
        Ok(self)
    }
}

impl<'a, T> Mask<&'a NBytes<T>> for Context where Self: Mask<NBytes<&'a T>> {
    fn mask(&mut self, nbytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.mask(NBytes::new(nbytes.inner()))
    }
}

/// Mask bytes, the size prefixed before the content bytes is also masked.
impl<T> Mask<Bytes<&T>> for Context where T: AsRef<[u8]> {
    fn mask(&mut self, bytes: Bytes<&T>) -> Result<&mut Self> {
        let size = Size::new(bytes.len());
        self.mask(size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

impl<'a, T> Mask<&'a Bytes<T>> for Context where Self: Mask<Bytes<&'a T>> {
    fn mask(&mut self, bytes: &'a Bytes<T>) -> Result<&mut Self> {
        self.mask(Bytes::new(bytes.inner()))
    }
}

impl Mask<&x25519::PublicKey> for Context {
    fn mask(&mut self, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

impl Mask<&ed25519::PublicKey> for Context {
    fn mask(&mut self, _pk: &ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

impl<T> Mask<Option<T>> for Context
where
    for<'b> &'b mut Self: Mask<T>,
{
    fn mask(&mut self, option: Option<T>) -> Result<&mut Self> {
        match option {
            // The hacky &mut is to break the recursivity of the trait bound. Not entirely sure if it shouldn't be
            // considered a Rust bug...
            Some(t) => (&mut self.mask(Uint8::new(1))?).mask(t)?,
            None => self.mask(Uint8::new(0))?,
        };
        Ok(self)
    }
}