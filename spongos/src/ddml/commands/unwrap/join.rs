use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::commands::{
        unwrap::Context,
        Join,
    },
};

impl<'a, F: PRP, IS> Join<F> for Context<IS, F> {
    fn join(&mut self, joinee: &mut Spongos<F>) -> Result<&mut Self> {
        self.spongos.join(joinee);
        Ok(self)
    }
}
