use anyhow::Result;

use super::Context;
use crate::{
    command::Dump,
    io,
};

impl<F, IS: io::IStream> Dump for Context<F, IS> {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        #[cfg(all(not(test), feature = "std"))]
        println!("dump: {}", args,);

        #[cfg(all(test, feature = "std"))]
        println!(
            "dump: {}: istream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
