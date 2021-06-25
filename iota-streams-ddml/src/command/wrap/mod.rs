//! Implementation of command traits for wrapping.

use iota_streams_core::sponge::{
    prp::PRP,
    spongos::*,
};

pub struct Context<F, OS> {
    pub spongos: Spongos<F>,
    pub stream: OS,
}

impl<F: PRP, OS> Context<F, OS> {
    pub fn new(stream: OS) -> Self {
        Self {
            spongos: Spongos::<F>::init(),
            stream,
        }
    }
}
#[allow(clippy::module_inception)]
mod wrap;
pub(crate) use wrap::*;

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
