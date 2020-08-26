use anyhow::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        NBytes,
    },
};
use iota_streams_core::sponge::prp::PRP;

/// This is just an external tag or hash value to-be-signed.
impl<'a, F, IS> Squeeze<&'a mut External<NBytes>> for Context<F, IS>
where
    F: PRP,
{
    fn squeeze(&mut self, val: &'a mut External<NBytes>) -> Result<&mut Self> {
        self.spongos.squeeze(&mut ((val.0).0)[..]);
        Ok(self)
    }
}
