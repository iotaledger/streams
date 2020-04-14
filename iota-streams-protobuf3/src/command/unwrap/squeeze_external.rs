use failure::Fallible;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        External,
        NTrytes,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};

/// This is just an external tag or hash value to-be-signed.
impl<'a, TW, F, IS> Squeeze<&'a mut External<NTrytes<TW>>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, val: &'a mut External<NTrytes<TW>>) -> Fallible<&mut Self> {
        self.spongos.squeeze(&mut ((val.0).0).slice_mut());
        Ok(self)
    }
}
