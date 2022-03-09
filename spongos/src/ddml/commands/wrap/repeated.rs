use core::iter;

use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Repeated,
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

impl<I, C, F, OS> Repeated<I, C> for Context<F, OS>
where
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: C) -> Result<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Result<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}
