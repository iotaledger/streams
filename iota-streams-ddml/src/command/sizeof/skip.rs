use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Skip,
    types::{
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        SkipFallback,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

/// Skipped values are just encoded.
/// All Uint8 values are encoded with 3 trits.
impl<F> Skip<Uint8> for Context<F> {
    fn skip(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint16 values are encoded with 3 trits.
impl<F> Skip<Uint16> for Context<F> {
    fn skip(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint32 values are encoded with 3 trits.
impl<F> Skip<Uint32> for Context<F> {
    fn skip(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint64 values are encoded with 3 trits.
impl<F> Skip<Uint64> for Context<F> {
    fn skip(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<F> Skip<Size> for Context<F> {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.sizeof() as usize;
        Ok(self)
    }
}

impl<'a, F> Skip<&'a Bytes> for Context<F> {
    fn skip(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        let bytes_size = Size(bytes.len());
        self.size += bytes_size.sizeof() as usize + bytes.len();
        Ok(self)
    }
}

impl<'a, F, N: ArrayLength<u8>> Skip<&'a NBytes<N>> for Context<F> {
    fn skip(&mut self, _nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

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
