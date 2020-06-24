use anyhow::Result;

use super::Context;
use crate::{
    command::Dump,
    io,
};

impl<F, IS: io::IStream> Dump for Context<F, IS>
{
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Result<&mut Self> {
        #[cfg(not(test))]
        println!("dump: {}", args,);

        #[cfg(test)]
        println!(
            "dump: {}: istream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
