use anyhow::Result;
use generic_array::ArrayLength;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Squeeze,
    },
    modifiers::External,
    types::{
        Mac,
        NBytes,
    },
};

/// Mac is just like NBytes.
impl Squeeze<&Mac> for Context {
    fn squeeze(&mut self, mac: &Mac) -> Result<&mut Self> {
        self.size += mac.length();
        Ok(self)
    }
}

/// Mac is just like NBytes.
impl Squeeze<Mac> for Context {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

/// External values are not encoded.
impl<T: AsRef<[u8]>> Squeeze<External<NBytes<&T>>> for Context {
    fn squeeze(&mut self, _external_nbytes: External<NBytes<&T>>) -> Result<&mut Self> {
        Ok(self)
    }
}

impl<'a, T> Squeeze<External<&'a NBytes<T>>> for Context
where
    Self: Squeeze<External<NBytes<&'a T>>>,
{
    fn squeeze(&mut self, external_nbytes: External<&'a NBytes<T>>) -> Result<&mut Self> {
        self.squeeze(External::new(NBytes::new(external_nbytes.into_inner().inner())))
    }
}

/// External values are not encoded.
impl Squeeze<External<Mac>> for Context {
    fn squeeze(&mut self, _mac: External<Mac>) -> Result<&mut Self> {
        Ok(self)
    }
}

// Implement &External<T> for any External<&T> implementation
impl<'a, T> Squeeze<&'a External<T>> for Context
where
    Self: Squeeze<External<&'a T>>,
{
    fn squeeze(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.squeeze(External::new(external.inner()))
    }
}
