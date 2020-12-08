use iota_streams_core::Result;

use super::Context;
use crate::command::Commit;
use iota_streams_core::sponge::prp::PRP;

/// Commit Spongos.
impl<F: PRP, OS> Commit for Context<F, OS> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
