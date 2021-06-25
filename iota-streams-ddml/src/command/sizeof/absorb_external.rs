use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Absorb,
    types::{
        AbsorbExternalFallback,
        ArrayLength,
        External,
        Fallback,
        NBytes,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

// External values are not encoded in the stream.
impl<F> Absorb<External<Uint8>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint8>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint16>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint16>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint32>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint32>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint64>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint64>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the trinary stream.
impl<'a, F, N: ArrayLength<u8>> Absorb<External<&'a NBytes<N>>> for Context<F> {
    fn absorb(&mut self, _external: External<&'a NBytes<N>>) -> Result<&mut Self> {
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>> Absorb<External<Fallback<&'a T>>> for Context<F> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}
