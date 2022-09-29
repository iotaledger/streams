use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::commands::{wrap::Context, Commit},
};

/// Commit [`Spongos`] state.
impl<F: PRP, OS> Commit for Context<OS, F> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
