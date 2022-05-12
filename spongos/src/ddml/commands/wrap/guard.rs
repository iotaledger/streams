use anyhow::{
    ensure,
    Result,
};

use crate::ddml::commands::{
    wrap::Context,
    Guard,
};

impl<'a, OS, F> Guard for Context<OS, F> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self>
    where
        E: Into<anyhow::Error>,
    {
        ensure!(cond, err);
        Ok(self)
    }
}
