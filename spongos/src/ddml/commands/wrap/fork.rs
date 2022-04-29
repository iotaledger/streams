use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Fork,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

impl<'a, F, OS> Fork<'a> for Context<F, OS>
where
    F: Clone,
    OS: 'a,
{
    type Forked = Context<F, &'a mut OS>;
    fn fork(&'a mut self) -> Context<F, &'a mut OS> {
        let fork = self.spongos.fork();
        Context::new_with_spongos(self.stream_mut(), fork)
    }
}
