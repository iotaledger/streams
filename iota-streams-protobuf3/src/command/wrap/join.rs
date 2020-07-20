use anyhow::Result;

use super::Context;
use crate::{
    command::Join,
    io,
    types::{
        LinkStore,
        SkipFallback,
    },
};
use iota_streams_core::sponge::prp::PRP;

/*
impl<'a, F, L, S: LinkStore<F, L>, OS: io::OStream> Join<&'a L, &'a S> for Context<F, OS> where
    Self: Skip<&'a L>
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
        let (mut s, i) = store.lookup(link)?;
        self.skip(link)?;
        self.spongos.join(&mut s);(self)
    }
}
 */

impl<'a, F, L: SkipFallback<F>, S: LinkStore<F, L>, OS: io::OStream> Join<&'a L, &'a S> for Context<F, OS>
where
    F: PRP,
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
        //TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        link.wrap_skip(self)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
