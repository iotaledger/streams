use failure::Fallible;

use super::Context;
use crate::command::Dump;

impl<TW, F> Dump for Context<TW, F> {
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Fallible<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
