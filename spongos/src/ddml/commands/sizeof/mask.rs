use crypto::{keys::x25519, signatures::ed25519};
use generic_array::typenum::Unsigned;

use crate::{
    core::{prp::PRP, spongos::Spongos},
    ddml::{
        commands::{sizeof::Context, Mask},
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
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
impl<T: AsRef<[u8]>> Mask<NBytes<T>> for Context {
    fn mask(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.inner().as_ref().len();
        Ok(self)
    }
}

/// Mask bytes, the size prefixed before the content bytes is also masked.
impl<T> Mask<Bytes<T>> for Context
where
    T: AsRef<[u8]>,
{
    fn mask(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        let size = Size::new(bytes.len());
        self.mask(size)?;
        self.size += bytes.len();
        Ok(self)
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

impl<F> Mask<&Spongos<F>> for Context
where
    F: PRP,
{
    fn mask(&mut self, _spongos: &Spongos<F>) -> Result<&mut Self> {
        self.size += F::CapacitySize::USIZE + F::RateSize::USIZE;
        Ok(self)
    }
}

impl<T> Mask<Maybe<Option<T>>> for Context
where
    for<'a> Self: Mask<T> + Mask<&'a ()>,
{
    fn mask(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            Some(t) => self.mask(Uint8::new(1))?.mask(t)?,
            None => self.mask(Uint8::new(0))?,
        };
        Ok(self)
    }
}

impl<'a> Mask<&'a ()> for Context {
    fn mask(&mut self, _: &'a ()) -> Result<&mut Self> {
        Ok(self)
    }
}
