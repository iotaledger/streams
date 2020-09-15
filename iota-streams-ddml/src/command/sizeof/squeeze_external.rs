use anyhow::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        Mac,
        NBytes,
        ArrayLength,
    },
};

/// External values are not encoded.
impl<'a, F, N: ArrayLength<u8>> Squeeze<&'a External<NBytes<N>>> for Context<F> {
    fn squeeze(&mut self, _external_nbytes: &'a External<NBytes<N>>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl<F> Squeeze<&External<Mac>> for Context<F> {
    fn squeeze(&mut self, _mac: &External<Mac>) -> Result<&mut Self> {
        Ok(self)
    }
}
