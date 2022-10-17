use crate::{
    ddml::commands::{wrap::Context, Guard},
    error::{Error, Result},
};

/// Ensures that the provided condition is met
impl<OS, F> Guard for Context<OS, F> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self>
    where
        E: Into<Error>,
    {
        match cond {
            true => Ok(self),
            false => Err(err.into()),
        }
    }
}
