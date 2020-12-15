use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Join,
    link_store::LinkStore,
    types::SkipFallback,
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

/// It's the size of the link.
impl<'a, F, L: SkipFallback<F>, S: LinkStore<F, L>> Join<&'a L, &'a S> for Context<F> {
    fn join(&mut self, _store: &'a S, link: &'a L) -> Result<&mut Self> {
        link.sizeof_skip(self)?;
        Ok(self)
    }
}
