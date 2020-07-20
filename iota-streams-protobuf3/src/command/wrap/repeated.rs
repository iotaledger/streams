use anyhow::Result;
use core::iter;

use super::Context;
use crate::{
    command::Repeated,
    io,
};
use iota_streams_core::sponge::prp::PRP;

impl<I, C, F, OS: io::OStream> Repeated<I, C> for Context<F, OS>
where
    F: PRP,
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
