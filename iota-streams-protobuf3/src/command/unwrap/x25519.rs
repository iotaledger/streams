use anyhow::Result;

use super::Context;
use crate::{
    io,
    command::X25519,
    types::NBytes,
};
use iota_streams_core_edsig::key_exchange::x25519;

/// Sizeof encapsulated secret is fixed.
impl<F, IS: io::IStream> X25519<&x25519::StaticSecret, &mut NBytes> for Context<F, IS>
{
    fn x25519(&mut self, _key: &x25519::StaticSecret, _secret: &mut NBytes) -> Result<&mut Self> {
        //TODO: Ensure key is valid.
        Ok(self)
    }
}
