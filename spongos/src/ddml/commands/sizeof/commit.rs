use anyhow::Result;

use crate::ddml::commands::{
    sizeof::Context,
    Commit,
};

/// Commit costs nothing in the trinary stream.
impl<F> Commit for Context<F> {
    fn commit(&mut self) -> Result<&mut Self> {
        Ok(self)
    }
}
