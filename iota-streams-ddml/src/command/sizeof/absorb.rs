use anyhow::Result;

use super::Context;
use crate::{
    command::Absorb,
    types::{
        sizeof_sizet,
        AbsorbFallback,
        Bytes,
        Fallback,
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

/// All Uint8 values are encoded with 1 byte.
impl<F> Absorb<&Uint8> for Context<F> {
    fn absorb(&mut self, _u: &Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<F> Absorb<&Size> for Context<F> {
    fn absorb(&mut self, size: &Size) -> Result<&mut Self> {
        self.size += sizeof_sizet(size.0);
        Ok(self)
    }
}

/// All Uint8 values are encoded with 1 byte.
impl<F> Absorb<Uint8> for Context<F> {
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

/// Size has var-size encoding.
impl<F> Absorb<Size> for Context<F> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

/// `bytes` has variable size thus the size is encoded before the content bytes.
impl<'a, F> Absorb<&'a Bytes> for Context<F> {
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.size += sizeof_sizet((bytes.0).len()) + (bytes.0).len();
        Ok(self)
    }
}

/// `bytes` has variable size thus the size is encoded before the content bytes.
impl<F> Absorb<Bytes> for Context<F> {
    fn absorb(&mut self, bytes: Bytes) -> Result<&mut Self> {
        self.absorb(&bytes)
    }
}

/// `byte [n]` is fixed-size and is encoded with `n` bytes.
impl<'a, F, N: ArrayLength<u8>> Absorb<&'a NBytes<N>> for Context<F> {
    fn absorb(&mut self, _nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

/// `byte [n]` is fixed-size and is encoded with `n` bytes.
impl<F, N: ArrayLength<u8>> Absorb<NBytes<N>> for Context<F> {
    fn absorb(&mut self, nbytes: NBytes<N>) -> Result<&mut Self> {
        self.absorb(&nbytes)
    }
}

/// MSS public key has fixed size.
impl<'a, F> Absorb<&'a ed25519::PublicKey> for Context<F> {
    fn absorb(&mut self, _pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        self.size += ed25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

/// NTRU public key has fixed size.
impl<'a, F> Absorb<&'a x25519::PublicKey> for Context<F> {
    fn absorb(&mut self, _pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

// It's the size of the link.
// impl<'a, F, L: Link> Absorb<&'a L> for Context<F> {
// fn absorb(&mut self, link: &'a L) -> Result<&mut Self> {
// self.size += link.len();
// Ok(self)
// }
// }

/// It's the size of the link.
impl<'a, F, T: 'a + AbsorbFallback<F>> Absorb<&'a Fallback<T>> for Context<F> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).sizeof_absorb(self)?;
        Ok(self)
    }
}
