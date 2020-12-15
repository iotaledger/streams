use iota_streams_core::Result;

use super::Context;
use crate::command::Dump;
use iota_streams_core::println;

impl<F> Dump for Context<F> {
    #[allow(unused_variables)]
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
