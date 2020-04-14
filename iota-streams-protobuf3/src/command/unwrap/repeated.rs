use failure::Fallible;

use super::Context;
use crate::{
    command::Repeated,
    io,
    types::Size,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

impl<C, TW, F, IS: io::IStream<TW>> Repeated<Size, C> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, n: Size, mut value_handle: C) -> Fallible<&mut Self> {
        for _ in 0..(n.0) {
            value_handle(self)?;
        }
        Ok(self)
    }
}
