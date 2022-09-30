use anyhow::{ensure, Result};

use crate::ddml::commands::{unwrap::Context, Guard};

/// Ensures that the provided condition is met
impl<IS, F> Guard for Context<IS, F> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self>
    where
        E: Into<anyhow::Error>,
    {
        ensure!(cond, err);
        Ok(self)
    }
}
