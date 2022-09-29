use crate::{
    ddml::{
        commands::{sizeof::Context, Absorb},
        modifiers::External,
        types::{NBytes, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
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
impl<T: AsRef<[u8]>> Absorb<External<&NBytes<T>>> for Context {
    fn absorb(&mut self, _external: External<&NBytes<T>>) -> Result<&mut Self> {
        Ok(self)
    }
}
