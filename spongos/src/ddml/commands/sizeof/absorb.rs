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
impl<F> Absorb<Uint8> for Context<F> {
    fn absorb(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// All Uint16 values are encoded with 2 bytes.
impl<F> Absorb<Uint16> for Context<F> {
    fn absorb(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// All Uint32 values are encoded with 4 bytes.
impl<F> Absorb<Uint32> for Context<F> {
    fn absorb(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// All Uint64 values are encoded with 8 bytes.
impl<F> Absorb<Uint64> for Context<F> {
    fn absorb(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<F> Absorb<Size> for Context<F> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// `bytes` has variable size thus the size is encoded before the content bytes.
impl<'a, F> Absorb<&'a Bytes> for Context<F> {
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.absorb(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// `byte [n]` is fixed-size and is encoded with `n` bytes.
impl<'a, F, N: ArrayLength<u8>> Absorb<&'a NBytes<N>> for Context<F> {
    fn absorb(&mut self, _nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

/// ed25519 public key has fixed size of 32 bytes.
impl<'a, F> Absorb<&'a ed25519::PublicKey> for Context<F> {
    fn absorb(&mut self, _pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// X25519 public key has fixed size of 32 bytes.
impl<'a, F> Absorb<&'a x25519::PublicKey> for Context<F> {
    fn absorb(&mut self, _pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

// TODO: REMOVE (and replace by impl)
// impl<'a, F, T: 'a + AbsorbFallback<F>> Absorb<&'a Fallback<T>> for Context<F> {
//     fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
//         (val.0).sizeof_absorb(self)?;
//         Ok(self)
//     }
// }

/// External values are not encoded in the stream.
impl<F> Absorb<External<Uint8>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint8>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl<F> Absorb<External<Uint16>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint16>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl<F> Absorb<External<Uint32>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint32>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the stream.
impl<F> Absorb<External<Uint64>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint64>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the binary stream.
impl<F, N: ArrayLength<u8>> Absorb<External<&NBytes<N>>> for Context<F> {
    fn absorb(&mut self, _external: External<&NBytes<N>>) -> Result<&mut Self> {
        Ok(self)
    }
}
