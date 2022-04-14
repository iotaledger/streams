//! Implementation of command traits for calculating the size for output buffer in Wrap operation.

/// Message size counting context.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Context {
    size: usize,
}

impl Context {
    /// Creates a new Context<F>.
    pub fn new() -> Self {
        Self {
            size: 0,
        }
    }

    /// Returns calculated message size.
    pub fn size(&self) -> usize {
        self.size
    }
}

mod absorb;
mod commit;
mod dump;
mod fork;
mod join;
mod mask;
mod repeated;
mod skip;
mod squeeze;

mod ed25519;
mod x25519;

// TODO: REMOVE
// mod absorb_external;
// mod squeeze_external;

// TODO: REMOVE
// use absorb::*;
// use absorb_external::*;
// use commit::*;
// use dump::*;
// use fork::*;
// use join::*;
// use mask::*;
// use repeated::*;
// use skip::*;
// use squeeze::*;
// use squeeze_external::*;

// use ed25519::*;
// use x25519::*;
