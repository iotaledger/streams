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

/// Increases [`Context`] size by 1 byte, representing the number of masking bytes for all Uint8
/// values.
impl Mask<Uint8> for Context {
    fn mask(&mut self, _val: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Increases [`Context`] size by 2 bytes, representing the number of masking bytes for all Uint16
/// values.
impl Mask<Uint16> for Context {
    fn mask(&mut self, _val: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Increases [`Context`] size by 4 bytes, representing the number of masking bytes for all Uint32
/// values.
impl Mask<Uint32> for Context {
    fn mask(&mut self, _val: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Increases [`Context`] size by 8 bytes, representing the number of masking bytes for all Uint64
/// values.
impl Mask<Uint64> for Context {
    fn mask(&mut self, _val: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Size`] wrapper.
/// `Size` has var-size encoding.
impl Mask<Size> for Context {
    fn mask(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`NBytes`] wrapper.
/// `NByte<bytes[n]>` is fixed-size and is masked with `n` bytes.
impl<T: AsRef<[u8]>> Mask<NBytes<T>> for Context {
    fn mask(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.inner().as_ref().len();
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Bytes`] wrapper.
/// `Bytes<bytes[n]>` has variable size thus the size `n` is masked before the content bytes.
impl<T: AsRef<[u8]>> Mask<Bytes<T>> for Context {
    fn mask(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        let size = Size::new(bytes.len());
        self.mask(size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// Increases [`Context`] size by the fixed size of an x25519 public key (32 bytes).
impl Mask<&x25519::PublicKey> for Context {
    fn mask(&mut self, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// Increases [`Context`] size by the fixed size of an ed25519 public key (32 bytes).
impl Mask<&ed25519::PublicKey> for Context {
    fn mask(&mut self, _pk: &ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// Increases [`Context`] size by the fixed size of a [`Spongos`] (CapacitySize + RateSize bytes).
impl<F: PRP> Mask<&Spongos<F>> for Context {
    fn mask(&mut self, _spongos: &Spongos<F>) -> Result<&mut Self> {
        self.size += F::CapacitySize::USIZE + F::RateSize::USIZE;
        Ok(self)
    }
}

/// Masks a [`Maybe`] wrapper for an `Option` into the [`Context`] size. If the `Option` is `Some`,
/// a `Uint8(1)` value is masked first, followed by the content. If the `Option` is `None`, only a
/// `Uint8(0)` is masked.
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
