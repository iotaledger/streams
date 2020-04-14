use failure::Fallible;

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

/// External values are not encoded.
impl<'a, TW, F, OS: io::OStream<TW>> Squeeze<&'a Mac> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, mac: &'a Mac) -> Fallible<&mut Self> {
        self.spongos.squeeze(&mut self.stream.try_advance(mac.0)?);
        Ok(self)
    }
}
