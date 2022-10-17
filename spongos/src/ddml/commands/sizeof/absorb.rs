use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    ddml::{
        commands::{sizeof::Context, Absorb},
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// Increases [`Context`] size by 1 byte, representing the number of encoded bytes for all Uint8
/// values.
impl Absorb<Uint8> for Context {
    fn absorb(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Increases [`Context`] size by 2 bytes, representing the number of encoded bytes for all Uint16
/// values.
impl Absorb<Uint16> for Context {
    fn absorb(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Increases [`Context`] size by 4 bytes, representing the number of encoded bytes for all Uint32
/// values.
impl Absorb<Uint32> for Context {
    fn absorb(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Increases [`Context`] size by 8 bytes, representing the number of encoded bytes for all Uint64
/// values.
impl Absorb<Uint64> for Context {
    fn absorb(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Size`] wrapper.
/// `Size` has var-size encoding.
impl Absorb<Size> for Context {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Bytes`] wrapper.
/// `Bytes<bytes[n]>` has variable size thus the size `n` is encoded before the content bytes.
impl<T: AsRef<[u8]>> Absorb<Bytes<T>> for Context {
    fn absorb(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.absorb(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`NBytes`] wrapper.
/// `NByte<bytes[n]>` is fixed-size and is encoded with `n` bytes.
impl<T: AsRef<[u8]>> Absorb<NBytes<T>> for Context {
    fn absorb(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.inner().as_ref().len();
        Ok(self)
    }
}

/// Increases [`Context`] size by the fixed size of an ed25519 public key (32 bytes).
impl Absorb<&ed25519::PublicKey> for Context {
    fn absorb(&mut self, _pk: &ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// Increases [`Context`] size by the fixed size of an x25519 public key (32 bytes).
impl Absorb<&x25519::PublicKey> for Context {
    fn absorb(&mut self, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// Absorbs a [`Maybe`] wrapper for an `Option` into the [`Context`] size. If the `Option` is
/// `Some`, a `Uint8(1)` value is absorbed first, followed by the content. If the `Option` is
/// `None`, only a `Uint8(0)` is absorbed.
impl<T> Absorb<Maybe<Option<T>>> for Context
where
    Self: Absorb<T>,
{
    fn absorb(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            // for some reason fully qualified syntax is necessary, and cannot use the trait bound like in wrap::Context
            Some(t) => <Self as Absorb<Uint8>>::absorb(self, Uint8::new(1))?.absorb(t)?,
            None => <Self as Absorb<Uint8>>::absorb(self, Uint8::new(0))?,
        };
        Ok(self)
    }
}
