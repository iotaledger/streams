use core::fmt::{Debug, Display};

use anyhow::{
    ensure,
    Result,
};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::Context,
            Guard,
        },
        io,
    },
    error::Error,
};

impl<F, IS> Guard for Context<F, IS> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self> where E: Into<anyhow::Error> {
        ensure!(cond, err);
        Ok(self)
    }
}