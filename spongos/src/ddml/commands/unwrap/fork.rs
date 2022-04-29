use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::Context,
            Fork,
        },
        io,
    },
};

impl<'a, F, IS> Fork<'a> for Context<F, IS>
where
    F: Clone,
    IS: 'a,
{
    type Forked = Context<F, &'a mut IS>;
    fn fork(&'a mut self) -> Context<F, &'a mut IS> {
        let fork = self.spongos.fork();
        Context::new_with_spongos(self.stream_mut(), fork)
    }
}
