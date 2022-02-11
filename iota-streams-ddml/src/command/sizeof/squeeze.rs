use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::Mac,
};

/// Mac is just like NBytes.
impl<F> Squeeze<&Mac> for Context<F> {
    fn squeeze(&mut self, mac: &Mac) -> Result<&mut Self> {
        self.size += mac.0;
        Ok(self)
    }
}

/// Mac is just like NBytes.
impl<F> Squeeze<Mac> for Context<F> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}
