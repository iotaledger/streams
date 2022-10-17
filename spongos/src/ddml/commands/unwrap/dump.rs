use crate::{
    core::prp::PRP,
    ddml::{
        commands::{unwrap::Context, Dump},
        io,
    },
    error::Result,
};

/// Displays [`Context`] stream and spongos
impl<F: PRP, IS: io::IStream> Dump for Context<IS, F> {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        println!(
            "dump: {}: istream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );

        Ok(self)
    }
}
