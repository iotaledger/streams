use anyhow::Result;

use super::Context;
use crate::{
    command::Skip,
    types::{
        sizeof_sizet,
        Bytes,
        Fallback,
        NBytes,
        ArrayLength,
        Size,
        SkipFallback,
        Uint8,
    },
};

/// Skipped values are just encoded.
/// All Uint8 values are encoded with 3 trits.
impl<F> Skip<&Uint8> for Context<F> {
    fn skip(&mut self, _u: &Uint8) -> Result<&mut Self> {
        self.size += 3;
        Ok(self)
    }
}

/// All Uint8 values are encoded with 3 trits.
impl<F> Skip<Uint8> for Context<F> {
    fn skip(&mut self, u: Uint8) -> Result<&mut Self> {
        self.skip(&u)
    }
}

/// Size has var-size encoding.
impl<F> Skip<&Size> for Context<F> {
    fn skip(&mut self, size: &Size) -> Result<&mut Self> {
        self.size += sizeof_sizet(size.0);
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<F> Skip<Size> for Context<F> {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        self.skip(&size)
    }
}

/// `trytes` is encoded with `sizeof_sizet(n) + 3 * n` trits.
impl<'a, F> Skip<&'a Bytes> for Context<F> {
    fn skip(&mut self, trytes: &'a Bytes) -> Result<&mut Self> {
        self.size += sizeof_sizet((trytes.0).len()) + (trytes.0).len();
        Ok(self)
    }
}

/// `trytes` is encoded with `sizeof_sizet(n) + 3 * n` trits.
impl<F> Skip<Bytes> for Context<F> {
    fn skip(&mut self, trytes: Bytes) -> Result<&mut Self> {
        self.skip(&trytes)
    }
}

/// `tryte [n]` is encoded with `3 * n` trits.
impl<'a, F, N: ArrayLength<u8>> Skip<&'a NBytes<N>> for Context<F> {
    fn skip(&mut self, _nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

/// `tryte [n]` is encoded with `3 * n` trits.
impl<F, N: ArrayLength<u8>> Skip<NBytes<N>> for Context<F> {
    fn skip(&mut self, nbytes: NBytes<N>) -> Result<&mut Self> {
        self.skip(&nbytes)
    }
}

impl<'a, F, T: 'a + SkipFallback<F>> Skip<&'a Fallback<T>> for Context<F> {
    fn skip(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).sizeof_skip(self)?;
        Ok(self)
    }
}
