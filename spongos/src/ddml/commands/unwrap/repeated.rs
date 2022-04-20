use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            unwrap::Context,
            Repeated,
        },
        io,
    },
};

impl<C, F, IS> Repeated<usize, C> for Context<F, IS>
where
    C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, n: usize, mut handle: C) -> Result<&mut Self> {
        for _ in 0..n {
            handle(self)?;
        }
        Ok(self)
    }
}
