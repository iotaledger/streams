use core::iter;

use anyhow::Result;

use crate::ddml::commands::{
    wrap::Context,
    Repeated,
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
