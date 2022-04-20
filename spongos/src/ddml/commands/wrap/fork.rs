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

// TODO
// impl<F, OS> Fork for Context<F, OS>
// where
//     F: Clone,
// {
//     type Forked<'a> = Context<F, &'a mut OS>;

//     fn fork(&mut self) -> Context<F, &mut OS> {
//         let fork = self.spongos.fork();
//         Context::new_with_spongos(self.stream_mut(), fork)
//     }
// }
