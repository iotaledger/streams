use core::iter;

use crate::{
    ddml::commands::{sizeof::Context, Repeated},
    error::Result,
};

/// Repeated modifier. The actual number of repetitions must be wrapped
/// (absorbed/masked/skipped) explicitly.
impl<I, C> Repeated<I, C> for Context
where
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, I::Item) -> Result<&'a mut Self>,
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
