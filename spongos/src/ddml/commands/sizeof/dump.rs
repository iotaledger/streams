use crate::{
    ddml::commands::{sizeof::Context, Dump},
    error::Result,
};

/// Displays context size
impl Dump for Context {
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
