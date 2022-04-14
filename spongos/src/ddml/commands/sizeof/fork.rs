use anyhow::Result;

use crate::ddml::commands::{
    sizeof::Context,
    Fork,
};

/// Forks cost nothing in the binary stream.
impl<C> Fork<C> for Context
where
    C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Result<&mut Self> {
        cont(self)
    }
}
