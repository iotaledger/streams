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

// TODO: REMOVE
// impl<C, F: Clone, IS> Fork<C> for Context<F, IS>
// where
//     C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
// {
//     fn fork(&mut self, mut cont: C) -> Result<&mut Self> {
//         let saved_fork = self.spongos.fork();
//         cont(self)?;
//         self.spongos = saved_fork;
//         Ok(self)
//     }
// }

// TODO
// impl<F, IS> Fork for Context<F, IS> where F: Clone
// {
//     fn fork(&mut self) -> Context<F, &mut IS> {
//         let fork = self.spongos.fork();
//         Context::new_with_spongos(self.stream_mut(), fork)
//     }
// }