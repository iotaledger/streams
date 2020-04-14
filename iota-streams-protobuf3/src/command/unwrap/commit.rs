use failure::Fallible;

use super::Context;
use crate::command::Commit;
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

/// Commit Spongos.
impl<TW, F, IS> Commit for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn commit(&mut self) -> Fallible<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
