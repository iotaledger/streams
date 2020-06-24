use anyhow::Result;

use super::Context;
use crate::{
    command::Dump,
    io,
};

impl<F, OS: io::OStream> Dump for Context<F, OS>
{
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Result<&mut Self> {
        #[cfg(not(test))]
        println!("dump: {}", args,);

        #[cfg(test)]
        println!(
            "dump: {}: ostream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
