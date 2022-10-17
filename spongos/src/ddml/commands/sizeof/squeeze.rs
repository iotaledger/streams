use crate::{
    ddml::{
        commands::{sizeof::Context, Squeeze},
        modifiers::External,
        types::{Mac, NBytes},
    },
    error::Result,
};

/// Increases [`Context`] size by the number of bytes present in a [`Mac`] wrapper.
/// Mac is just like NBytes.
impl Squeeze<&Mac> for Context {
    fn squeeze(&mut self, mac: &Mac) -> Result<&mut Self> {
        self.size += mac.length();
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in a [`Mac`] wrapper.
/// Mac is just like NBytes.
impl Squeeze<Mac> for Context {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

/// External values are not encoded.
impl<T: AsRef<[u8]>> Squeeze<External<&NBytes<T>>> for Context {
    fn squeeze(&mut self, _external_nbytes: External<&NBytes<T>>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl Squeeze<External<Mac>> for Context {
    fn squeeze(&mut self, _mac: External<Mac>) -> Result<&mut Self> {
        Ok(self)
    }
}
