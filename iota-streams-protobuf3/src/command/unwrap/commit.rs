use anyhow::Result;

use super::Context;
use crate::command::Commit;
use iota_streams_core::sponge::prp::PRP;

/// Commit Spongos.
impl<F, IS> Commit for Context<F, IS>
where
    F: PRP,
{
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
