use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Squeeze,
    io,
    types::Mac,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

/// External values are not encoded. Squeeze and compare tag trits.
impl<'a, TW, F, IS: io::IStream<TW>> Squeeze<&'a Mac> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, val: &'a Mac) -> Fallible<&mut Self> {
        ensure!(
            self.spongos.squeeze_eq(self.stream.try_advance(val.0)?),
            "Integrity is violated, bad MAC."
        );
        Ok(self)
    }
}
