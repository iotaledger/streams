use anyhow::Result;

use crate::ddml::commands::{sizeof::Context, Commit};

/// Commit costs nothing in the trinary stream.
impl Commit for Context {
    fn commit(&mut self) -> Result<&mut Self> {
        Ok(self)
    }
}
