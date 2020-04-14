use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Guard,
    io,
};

impl<TW, F, IS: io::IStream<TW>> Guard for Context<TW, F, IS> {
    fn guard(&mut self, cond: bool, msg: &str) -> Fallible<&mut Self> {
        ensure!(cond, "guard: {}", msg);
        Ok(self)
    }
}
