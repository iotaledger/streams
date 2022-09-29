//! Implementation of command traits for calculating the size for output buffer in Wrap operation.

/// Message size counting context.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Context {
    size: usize,
}

/// Context for determining required stream size for wrapping.
impl Context {
    /// Creates a new [Context<F>]([`Context`]).
    pub fn new() -> Self {
        Self { size: 0 }
    }

    /// Returns calculated message size.
    pub fn finalize(self) -> usize {
        self.size
    }
}

mod absorb;
mod absorb_external;
mod commit;
#[cfg(feature = "std")]
mod dump;
mod fork;
mod join;
mod mask;
mod repeated;
mod skip;
mod squeeze;

mod ed25519;
mod x25519;
