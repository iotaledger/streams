use anyhow::Result;

use super::Context;
use crate::{
    command::Squeeze,
    io,
    types::Mac,
};
use iota_streams_core::{
    sponge::prp::PRP,
};

/// External values are not encoded.
impl<'a, F, OS: io::OStream> Squeeze<&'a Mac> for Context<F, OS>
where
    F: PRP,
{
    fn squeeze(&mut self, mac: &'a Mac) -> Result<&mut Self> {
        self.spongos.squeeze(&mut self.stream.try_advance(mac.0)?);
        Ok(self)
    }
}
