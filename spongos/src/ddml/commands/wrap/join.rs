use crate::{
    core::{prp::PRP, spongos::Spongos},
    ddml::commands::{wrap::Context, Join},
    error::Result,
};

/// Absorbs the provided [`Spongos`] into the beginning of the current [`Context`] spongos.
impl<F: PRP, OS> Join<F> for Context<OS, F> {
    fn join(&mut self, joinee: &mut Spongos<F>) -> Result<&mut Self> {
        self.spongos.join(joinee);
        Ok(self)
    }
}
