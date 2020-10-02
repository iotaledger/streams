use anyhow::{
    ensure,
    Result,
};

use super::Context;
use crate::{
    command::Guard,
    io,
};

impl<F, IS: io::OStream> Guard for Context<F, IS> {
    fn guard(&mut self, cond: bool, msg: &str) -> Result<&mut Self> {
        ensure!(cond, "guard: {}", msg);
        Ok(self)
    }
}
