use anyhow::Result;

use crate::{
    core::spongos::Spongos,
    ddml::commands::{
        sizeof::Context,
        Join,
    },
};

// It's the size of the link.
// impl<'a, L: Link, S: LinkStore<L>> Join<&'a L, &'a S> for Context<F> {
// fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
// self.size += link.size();
// Ok(self)
// }
// }
//
// impl<'a, F, L, S: LinkStore<F, L>> Join<&'a L, &'a S> for Context<F> where
// Self: Skip<&'a L>
// {
// fn join(&mut self, _store: &'a S, link: &'a L) -> Result<&mut Self> {
// self.skip(link)
// }
// }

/// Join does not take any space in the binary stream.
impl<'a, F> Join<F> for Context {
    fn join(&mut self, _joinee: &mut Spongos<F>) -> Result<&mut Self> {
        Ok(self)
    }
}
