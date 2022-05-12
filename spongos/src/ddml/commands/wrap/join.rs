use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::commands::{
        wrap::Context,
        Join,
    },
};

impl<'a, F: PRP, OS> Join<F> for Context<OS, F> {
    fn join(&mut self, joinee: &mut Spongos<F>) -> Result<&mut Self> {
        self.spongos.join(joinee);
        Ok(self)
    }
}
