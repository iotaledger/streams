use failure::Fallible;

use super::Context;
use crate::{
    command::Join,
    io,
    types::{
        LinkStore,
        SkipFallback,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::word::SpongosTbitWord,
};

/*
impl<'a, TW, F, L, S: LinkStore<TW, F, L>, OS: io::OStream<TW>> Join<&'a L, &'a S> for Context<TW, F, OS> where
    Self: Skip<&'a L>
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        let (mut s, i) = store.lookup(link)?;
        self.skip(link)?;
        self.spongos.join(&mut s);(self)
    }
}
 */

impl<'a, TW, F, L: SkipFallback<TW, F>, S: LinkStore<TW, F, L>, OS: io::OStream<TW>> Join<&'a L, &'a S>
    for Context<TW, F, OS>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        //TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        link.wrap_skip(self)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
