#![no_std]

// Spongos requires heap allocation for Vectors and Strings
#[cfg_attr(all(test, not(feature = "std")), macro_use)]
extern crate alloc;

// Spongos requires the feature "std" for the Dump DDML command
#[cfg(feature = "std")]
#[macro_use]
extern crate std;

mod error;
use error::Error;

/// Core utility tools (spongos/prp/prng)
mod core;
/// A markup language toolset for encoding/decoding/encrypting/signing byte streams
pub mod ddml;

pub use crate::core::{
    prng::SpongosRng,
    prp::{keccak::KeccakF1600, PRP},
    spongos::Spongos,
};
