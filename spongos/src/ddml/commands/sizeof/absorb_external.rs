use anyhow::Result;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Absorb,
    },
    modifiers::External,
    types::{
        NBytes,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

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
impl<T: AsRef<[u8]>> Absorb<External<NBytes<&T>>> for Context {
    fn absorb(&mut self, _external: External<NBytes<&T>>) -> Result<&mut Self> {
        Ok(self)
    }
}

impl<'a, T> Absorb<External<&'a NBytes<T>>> for Context
where
    Self: Absorb<External<NBytes<&'a T>>>,
{
    fn absorb(&mut self, external: External<&'a NBytes<T>>) -> Result<&mut Self> {
        self.absorb(External::new(NBytes::new(external.into_inner().inner())))
    }
}

// Implement &External<T> for any External<&T> implementation
impl<'a, T> Absorb<&'a External<T>> for Context
where
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External::new(external.inner()))
    }
}
