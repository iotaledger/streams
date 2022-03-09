use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{Wrap, Context},
            Dump,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Bytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

#[cfg(feature = "std")]
impl<F: PRP, OS: io::OStream> Dump for Context<F, OS> {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        println!(
            "dump: {}: ostream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
