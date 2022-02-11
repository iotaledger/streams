use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Dump,
    io,
};
use iota_streams_core::{
    println,
    sponge::prp::PRP,
};

impl<F: PRP, IS: io::IStream> Dump for Context<F, IS> {
    #[allow(unused_variables)]
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        //#[cfg(not(test))]
        // println!("dump: {}", args,);

        //#[cfg(test)]
        println!(
            "dump: {}: istream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
