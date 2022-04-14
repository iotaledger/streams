use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use anyhow::Result;
use generic_array::ArrayLength;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Absorb,
    },
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

/// `bytes` has variable size thus the size is encoded before the content bytes.
impl<'a> Absorb<&'a Bytes> for Context {
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.absorb(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// `byte [n]` is fixed-size and is encoded with `n` bytes.
impl<'a, T: AsRef<[u8]>> Absorb<&'a NBytes<T>> for Context {
    fn absorb(&mut self, nbytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.as_ref().len();
        Ok(self)
    }
}

/// ed25519 public key has fixed size of 32 bytes.
impl<'a> Absorb<&'a ed25519::PublicKey> for Context {
    fn absorb(&mut self, _pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// X25519 public key has fixed size of 32 bytes.
impl<'a> Absorb<&'a x25519::PublicKey> for Context {
    fn absorb(&mut self, _pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

// TODO: REMOVE (and replace by impl)
// impl<'a, F, T: 'a + AbsorbFallback> Absorb<&'a Fallback<T>> for Context {
//     fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
//         (val.0).sizeof_absorb(self)?;
//         Ok(self)
//     }
// }

/// External values are not encoded in the stream.
impl Absorb<External<Uint8>> for Context {
    fn absorb(&mut self, _external: External<Uint8>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl Absorb<External<Uint16>> for Context {
    fn absorb(&mut self, _external: External<Uint16>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl Absorb<External<Uint32>> for Context {
    fn absorb(&mut self, _external: External<Uint32>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl Absorb<External<Uint64>> for Context {
    fn absorb(&mut self, _external: External<Uint64>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the binary stream.
impl<T: AsRef<[u8]>> Absorb<External<&NBytes<T>>> for Context {
    fn absorb(&mut self, _external: External<&NBytes<T>>) -> Result<&mut Self> {
        Ok(self)
    }
}
