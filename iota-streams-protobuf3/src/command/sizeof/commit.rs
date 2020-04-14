use failure::Fallible;

use super::Context;
use crate::command::Commit;

/// Commit costs nothing in the trinary stream.
impl<TW, F> Commit for Context<TW, F> {
    fn commit(&mut self) -> Fallible<&mut Self> {
        Ok(self)
    }
}
