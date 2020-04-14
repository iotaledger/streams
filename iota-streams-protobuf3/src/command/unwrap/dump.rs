use failure::Fallible;

use super::Context;
use crate::{
    command::Dump,
    io,
};
use iota_streams_core::tbits::word::BasicTbitWord;

impl<TW, F, IS: io::IStream<TW>> Dump for Context<TW, F, IS>
where
    TW: BasicTbitWord,
{
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Fallible<&mut Self> {
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
