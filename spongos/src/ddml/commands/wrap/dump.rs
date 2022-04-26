use anyhow::Result;
use generic_array::ArrayLength;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Dump,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
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
