use anyhow::Result;

use super::Context;
use crate::command::Dump;

impl<F> Dump for Context<F> {
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Result<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
