use crate::{
    core::prp::PRP,
    ddml::commands::{unwrap::Context, Commit},
    error::Result,
};

/// Commit [Spongos](`crate::core::spongos::Spongos`) state.
impl<F: PRP, IS> Commit for Context<IS, F> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
