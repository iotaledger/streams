use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Join,
    io,
    link_store::LinkStore,
    types::SkipFallback,
};
use iota_streams_core::sponge::prp::PRP;

impl<'a, F: PRP, L: SkipFallback<F>, S: LinkStore<F, L>, IS: io::IStream> Join<&'a mut L, &S> for Context<F, IS> {
    fn join(&mut self, store: &S, link: &'a mut L) -> Result<&mut Self> {
        // TODO: Move `skip` out of `join` and `skip` links explicitly.
        // That way it's easier to handle the case when the link is not found
        // and calling function can try to fetch and parse message for the link.
        // TODO: Implement a strategy (depth of recursion or max number of retries)
        // for such cases.
        link.unwrap_skip(self)?;
        // TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
