use anyhow::Result;

use super::Context;
use crate::{
    command::Dump,
    io,
};

impl<F, OS: io::OStream> Dump for Context<F, OS> {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        #[cfg(all(not(test), feature = "std"))]
        println!("dump: {}", args,);

        #[cfg(all(test, feature = "std"))]
        println!(
            "dump: {}: ostream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
