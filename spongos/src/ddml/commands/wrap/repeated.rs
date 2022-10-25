use core::iter;

use crate::{
    ddml::commands::{wrap::Context, Repeated},
    error::Result,
};

/// Repeat a provided function an explicitly dictated number of times.
impl<I, C, F, OS> Repeated<I, C> for Context<OS, F>
where
    I: iter::Iterator,
    C: for<'b> FnMut(&'b mut Self, <I as iter::Iterator>::Item) -> Result<&'b mut Self>,
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
