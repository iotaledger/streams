use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Squeeze,
    types::Mac,
};

/// Mac is just like NTrytes.
impl<TW, F> Squeeze<&Mac> for Context<TW, F> {
    fn squeeze(&mut self, mac: &Mac) -> Fallible<&mut Self> {
        ensure!(mac.0 % 3 == 0, "Trit size of `mac` must be a multiple of 3: {}.", mac.0);
        self.size += mac.0;
        Ok(self)
    }
}

/// Mac is just like NTrytes.
impl<TW, F> Squeeze<Mac> for Context<TW, F> {
    fn squeeze(&mut self, val: Mac) -> Fallible<&mut Self> {
        self.squeeze(&val)
    }
}
