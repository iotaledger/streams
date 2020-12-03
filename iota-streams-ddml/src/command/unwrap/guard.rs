use anyhow::Result;

use super::Context;
use crate::{
    command::Guard,
    io,
};
use iota_streams_core::{Errors, try_or, LOCATION_LOG};

impl<F, IS: io::IStream> Guard for Context<F, IS> {
    fn guard(&mut self, cond: bool, err: Errors) -> Result<&mut Self> {
        try_or!(cond, err)?;
        Ok(self)
    }
}
