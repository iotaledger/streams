use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Guard,
    io,
};
use iota_streams_core::{
    try_or,
    Errors,
};

impl<F, IS: io::OStream> Guard for Context<F, IS> {
    fn guard(&mut self, cond: bool, err: Errors) -> Result<&mut Self> {
        try_or!(cond, err)?;
        Ok(self)
    }
}
