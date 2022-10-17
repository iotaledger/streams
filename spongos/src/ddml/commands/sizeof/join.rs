use crate::{
    core::spongos::Spongos,
    ddml::commands::{sizeof::Context, Join},
    error::Result,
};

/// Join does not take any space in the binary stream.
impl<F> Join<F> for Context {
    fn join(&mut self, _joinee: &mut Spongos<F>) -> Result<&mut Self> {
        Ok(self)
    }
}
