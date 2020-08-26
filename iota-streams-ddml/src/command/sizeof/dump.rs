use anyhow::Result;

use super::Context;
use crate::command::Dump;

impl<F> Dump for Context<F> {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        #[cfg(feature = "std")]
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
