use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::commands::{
        wrap::Context,
        Commit,
    },
};

/// Commit Spongos.
impl<F: PRP, OS> Commit for Context<F, OS> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
