use anyhow::Result;

use super::Context;
use crate::{
    command::Guard,
    io,
};
use iota_streams_core::{ErrorHandler, Errors};

impl<F, IS: io::OStream> Guard for Context<F, IS> {
    fn guard(&mut self, cond: bool, err: Errors) -> Result<&mut Self> {
        ErrorHandler::try_or(cond, err)?;
        Ok(self)
    }
}
