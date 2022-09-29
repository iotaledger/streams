use anyhow::Result;

use crate::ddml::commands::{sizeof::Context, Commit};

/// Commit has no effect on [sizeof context](`Context`)
impl Commit for Context {
    fn commit(&mut self) -> Result<&mut Self> {
        Ok(self)
    }
}
