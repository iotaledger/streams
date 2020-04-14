//! Implementation of command traits for wrapping.

use iota_streams_core::{
    sponge::{
        prp::PRP,
        spongos::*,
    },
    tbits::word::SpongosTbitWord,
};

//#[derive(Debug)]
pub struct Context<TW, F, OS> {
    pub spongos: Spongos<TW, F>,
    pub stream: OS,
}

impl<TW, F, OS> Context<TW, F, OS>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    pub fn new(stream: OS) -> Self {
        Self {
            spongos: Spongos::<TW, F>::init(),
            stream: stream,
        }
    }
}

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

mod mssig;
mod ntrukem;

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

pub use mssig::*;
pub use ntrukem::*;
