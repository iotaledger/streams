use anyhow::{
    ensure,
    Result,
};

use crate::ddml::commands::{
    wrap::Context,
    Guard,
};

impl<F, IS> Guard for Context<F, IS> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self>
    where
        E: Into<anyhow::Error>,
    {
        ensure!(cond, err);
        Ok(self)
    }
}
