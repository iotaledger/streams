//! Implementation of command traits for unwrapping.

use iota_streams_core::Result;

use core::fmt;

use crate::{
    io,
    types::Size,
};
use iota_streams_core::sponge::{
    prp::PRP,
    spongos::*,
};

pub struct Context<F, IS> {
    pub spongos: Spongos<F>,
    pub stream: IS,
}

impl<F: PRP, IS> Context<F, IS> {
    pub fn new(stream: IS) -> Self {
        Self {
            spongos: Spongos::<F>::init(),
            stream,
        }
    }
}

impl<F, IS: io::IStream> Context<F, IS> {
    pub fn drop(&mut self, n: Size) -> Result<&mut Self> {
        self.stream.try_advance(n.0)?;
        Ok(self)
    }
}

impl<F, IS> fmt::Debug for Context<F, IS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{header: {:?}, ctx: {:?}}}", "self.header", "self.ctx")
    }
}

impl<F, IS> Clone for Context<F, IS>
where
    F: Clone,
    IS: Clone,
{
    fn clone(&self) -> Self {
        Self {
            spongos: self.spongos.clone(),
            stream: self.stream.clone(),
        }
    }
}
#[allow(clippy::module_inception)]
mod unwrap;

mod absorb;
mod absorb_external;
mod commit;
mod dump;
mod fork;
mod guard;
mod join;
mod mask;
mod repeated;
mod skip;
mod squeeze;
mod squeeze_external;

mod ed25519;
mod x25519;

pub use absorb::*;
pub use absorb_external::*;
pub use commit::*;
pub use dump::*;
pub use fork::*;
pub use guard::*;
pub use join::*;
pub use mask::*;
pub use repeated::*;
pub use skip::*;
pub use squeeze::*;
pub use squeeze_external::*;

pub use ed25519::*;
pub use x25519::*;
