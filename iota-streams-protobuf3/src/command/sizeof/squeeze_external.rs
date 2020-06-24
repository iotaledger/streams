use anyhow::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        Mac,
        NBytes,
    },
};

/// External values are not encoded.
impl<'a, F> Squeeze<&'a External<NBytes>> for Context<F> {
    fn squeeze(&mut self, _external_ntrytes: &'a External<NBytes>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl<F> Squeeze<&External<Mac>> for Context<F> {
    fn squeeze(&mut self, _mac: &External<Mac>) -> Result<&mut Self> {
        Ok(self)
    }
}
