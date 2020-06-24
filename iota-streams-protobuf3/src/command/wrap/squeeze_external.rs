use anyhow::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        NBytes,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
};

/// This is just an external tag or hash value to-be-signed.
impl<'a, F, OS> Squeeze<&'a mut External<NBytes>> for Context<F, OS>
where
    F: PRP,
{
    fn squeeze(&mut self, external_nbytes: &'a mut External<NBytes>) -> Result<&mut Self> {
        self.spongos.squeeze(&mut ((external_nbytes.0).0)[..]);
        Ok(self)
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, F, OS> Squeeze<External<&'a mut NBytes>> for Context<F, OS>
where
    F: PRP,
{
    fn squeeze(&mut self, external_nbytes: External<&'a mut NBytes>) -> Result<&mut Self> {
        self.spongos.squeeze(&mut ((external_nbytes.0).0)[..]);
        Ok(self)
    }
}
