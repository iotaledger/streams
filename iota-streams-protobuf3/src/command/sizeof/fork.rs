use failure::Fallible;

use super::Context;
use crate::command::Fork;

/// Forks cost nothing in the trinary stream.
impl<TW, F, C> Fork<C> for Context<TW, F>
where
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Fallible<&mut Self> {
        cont(self)
    }
}
