use failure::Fallible;
use std::iter;

use super::Context;
use crate::{
    command::Repeated,
    io,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

impl<I, C, TW, F, OS: io::OStream<TW>> Repeated<I, C> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: C) -> Fallible<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Fallible<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}
