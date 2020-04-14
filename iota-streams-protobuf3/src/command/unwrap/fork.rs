use failure::Fallible;

use super::Context;
use crate::{
    command::Fork,
    io,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

impl<C, TW, F, IS: io::IStream<TW>> Fork<C> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Clone,
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Fallible<&mut Self> {
        let saved_fork = self.spongos.fork();
        cont(self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}
