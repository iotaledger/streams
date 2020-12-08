use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Join,
    io,
    link_store::LinkStore,
    types::SkipFallback,
};
use iota_streams_core::sponge::prp::PRP;

impl<'a, F: PRP, L: SkipFallback<F>, S: LinkStore<F, L>, OS: io::OStream> Join<&'a L, &'a S> for Context<F, OS> {
    fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
        // TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        link.wrap_skip(self)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
