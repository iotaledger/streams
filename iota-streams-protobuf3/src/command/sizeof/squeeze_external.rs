use failure::Fallible;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        Mac,
        NTrytes,
    },
};

/// External values are not encoded.
impl<'a, TW, F> Squeeze<&'a External<NTrytes<TW>>> for Context<TW, F> {
    fn squeeze(&mut self, _external_ntrytes: &'a External<NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl<TW, F> Squeeze<&External<Mac>> for Context<TW, F> {
    fn squeeze(&mut self, _mac: &External<Mac>) -> Fallible<&mut Self> {
        Ok(self)
    }
}
