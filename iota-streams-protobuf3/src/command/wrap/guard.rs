use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Guard,
    io,
};

impl<TW, F, IS: io::OStream<TW>> Guard for Context<TW, F, IS> {
    fn guard(&mut self, cond: bool, msg: &str) -> Fallible<&mut Self> {
        ensure!(cond, "guard: {}", msg);
        Ok(self)
    }
}
