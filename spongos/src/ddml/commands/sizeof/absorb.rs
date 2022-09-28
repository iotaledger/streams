use anyhow::Result;
use crypto::{keys::x25519, signatures::ed25519};

use crate::ddml::{
    commands::{sizeof::Context, Absorb},
    types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
};

/// All Uint8 values are encoded with 1 byte.
impl Absorb<Uint8> for Context {
    fn absorb(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// All Uint16 values are encoded with 2 bytes.
impl Absorb<Uint16> for Context {
    fn absorb(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// All Uint32 values are encoded with 4 bytes.
impl Absorb<Uint32> for Context {
    fn absorb(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// All Uint64 values are encoded with 8 bytes.
impl Absorb<Uint64> for Context {
    fn absorb(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl Absorb<Size> for Context {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// `Bytes<bytes[n]>` has variable size thus the size `n` is encoded before the content bytes.
impl<T> Absorb<Bytes<T>> for Context
where
    T: AsRef<[u8]>,
{
    /// Increases context size by the number of bytes present in the provided `Bytes` wrapper. Absorbs
    /// a `Size` wrapper around the number of bytes to be absorbed, then absorbs the bytes themselves.
    ///
    /// Arguments:
    /// * `nbytes`: The NBytes<T> object that we want to absorb.
    ///
    /// Returns:
    /// A mutable reference to the `SizeCounter` struct.
    fn absorb(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.absorb(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// `NByte<bytes[n]>` is fixed-size and is encoded with `n` bytes.
impl<T: AsRef<[u8]>> Absorb<NBytes<T>> for Context {
    /// Increases context size by the number of bytes present in the provided `NBytes` wrapper.
    ///
    /// Arguments:
    /// * `nbytes`: The NBytes<T> object that we want to absorb.
    ///
    /// Returns:
    /// A mutable reference to the `SizeCounter` struct.
    fn absorb(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.inner().as_ref().len();
        Ok(self)
    }
}

/// ed25519 public key has fixed size of 32 bytes.
impl Absorb<&ed25519::PublicKey> for Context {
    /// Increases context size by Ed25519 Public Key Length (32 Bytes)
    fn absorb(&mut self, _pk: &ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// X25519 public key has fixed size of 32 bytes.
impl Absorb<&x25519::PublicKey> for Context {

    fn absorb(&mut self, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

impl<T> Absorb<Maybe<Option<T>>> for Context
where
    Self: Absorb<T>,
{
    /// Absorbs a `Maybe` wrapper for an `Option` into the spongos context. If the `Option` is `Some`,
    /// a `Uint8(1)` value is absorbed first, and then the content. If the `Option` is `None`, only a
    /// `Uint8(0)` is absorbed.
    ///
    /// Arguments:
    /// * `maybe`: the Maybe<Option<T>> to absorb
    ///
    /// Returns:
    /// Mutable reference for self context.
    fn absorb(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            // for some reason fully qualified syntax is necessary, and cannot use the trait bound like in wrap::Context
            Some(t) => <Self as Absorb<Uint8>>::absorb(self, Uint8::new(1))?.absorb(t)?,
            None => <Self as Absorb<Uint8>>::absorb(self, Uint8::new(0))?,
        };
        Ok(self)
    }
}
