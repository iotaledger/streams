use crate::{
    core::prp::PRP,
    ddml::commands::{wrap::Context, Commit},
    error::Result,
};

/// Commit [`Spongos`](`crate::core::spongos::Spongos`) state.
impl<F: PRP, OS> Commit for Context<OS, F> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
