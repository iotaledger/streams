use crate::{
    ddml::commands::{unwrap::Context, Repeated},
    error::Result,
};

/// Repeat a provided function an explicitly dictated number of times.
impl<C, F, IS> Repeated<usize, C> for Context<IS, F>
where
    C: for<'b> FnMut(&'b mut Self) -> Result<&'b mut Self>,
{
    fn repeated(&mut self, n: usize, mut handle: C) -> Result<&mut Self> {
        for _ in 0..n {
            handle(self)?;
        }
        Ok(self)
    }
}
