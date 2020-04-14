//! Implementation of command traits for unwrapping.

use failure::Fallible;

use crate::{
    io,
    types::Size,
};
use iota_streams_core::{
    sponge::{
        prp::PRP,
        spongos::*,
    },
    tbits::word::SpongosTbitWord,
};

//#[derive(Debug)]
pub struct Context<TW, F, IS> {
    pub spongos: Spongos<TW, F>,
    pub stream: IS,
}

impl<TW, F, IS> Context<TW, F, IS>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    pub fn new(stream: IS) -> Self {
        Self {
            spongos: Spongos::<TW, F>::init(),
            stream: stream,
        }
    }
}

impl<TW, F, IS: io::IStream<TW>> Context<TW, F, IS> {
    pub fn drop(&mut self, n: Size) -> Fallible<&mut Self> {
        self.stream.try_advance(n.0)?;
        Ok(self)
        //<IS as io::IStream<TW>>::try_advance(&mut self.stream, n)
    }
}

impl<TW, F, IS> Clone for Context<TW, F, IS>
where
    TW: Clone,
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
