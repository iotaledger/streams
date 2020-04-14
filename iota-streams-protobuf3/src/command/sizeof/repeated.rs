use failure::Fallible;
use std::iter;

use super::Context;
use crate::command::Repeated;

/// Repeated modifier. The actual number of repetitions must be wrapped
/// (absorbed/masked/skipped) explicitly.
impl<TW, F, I, C> Repeated<I, C> for Context<TW, F>
where
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: C) -> Fallible<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Fallible<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}
