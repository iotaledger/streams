use anyhow::Result;
use generic_array::ArrayLength;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Squeeze,
    },
    modifiers::External,
    types::{NBytes, Mac},
};

/// Mac is just like NBytes.
impl<F> Squeeze<&Mac> for Context<F> {
    fn squeeze(&mut self, mac: &Mac) -> Result<&mut Self> {
        self.size += mac.length();
        Ok(self)
    }
}

/// Mac is just like NBytes.
impl<F> Squeeze<Mac> for Context<F> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

/// External values are not encoded.
impl<F, N: ArrayLength<u8>> Squeeze<&External<NBytes<N>>> for Context<F> {
    fn squeeze(&mut self, _external_nbytes: &External<NBytes<N>>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl<F> Squeeze<&External<Mac>> for Context<F> {
    fn squeeze(&mut self, _mac: &External<Mac>) -> Result<&mut Self> {
        Ok(self)
    }
}
