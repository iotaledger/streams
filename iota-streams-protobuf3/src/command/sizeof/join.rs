use failure::Fallible;

use super::Context;
use crate::{
    command::Join,
    types::{
        LinkStore,
        SkipFallback,
    },
};

/*
/// It's the size of the link.
impl<'a, L: Link, S: LinkStore<L>> Join<&'a L, &'a S> for Context<TW, F> {
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        self.size += link.size();
        Ok(self)
    }
}

impl<'a, TW, F, L, S: LinkStore<TW, F, L>> Join<&'a L, &'a S> for Context<TW, F> where
    Self: Skip<&'a L>
{
    fn join(&mut self, _store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        self.skip(link)
    }
}
*/

/// It's the size of the link.
impl<'a, TW, F, L: SkipFallback<TW, F>, S: LinkStore<TW, F, L>> Join<&'a L, &'a S> for Context<TW, F> {
    fn join(&mut self, _store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        link.sizeof_skip(self)?;
        Ok(self)
    }
}
