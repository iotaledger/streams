use anyhow::{
    ensure,
    Result,
};

use super::Context;
use crate::{
    command::Squeeze,
    io,
    types::Mac,
};
use iota_streams_core::{
    sponge::prp::PRP,
};

/// External values are not encoded. Squeeze and compare tag trits.
impl<'a, F, IS: io::IStream> Squeeze<&'a Mac> for Context<F, IS>
where
    F: PRP,
{
    fn squeeze(&mut self, val: &'a Mac) -> Result<&mut Self> {
        ensure!(
            self.spongos.squeeze_eq(self.stream.try_advance(val.0)?),
            "Integrity is violated, bad MAC."
        );
        Ok(self)
    }
}
