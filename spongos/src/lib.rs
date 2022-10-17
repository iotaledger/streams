#![no_std]

// Spongos requires heap allocation for Vectors and Strings
#[cfg_attr(all(test, not(feature = "std")), macro_use)]
extern crate alloc;

// Spongos requires the feature "std" for the Dump DDML command
#[cfg(feature = "std")]
#[macro_use]
extern crate std;

mod core;
pub mod ddml;
pub mod error;

pub use crate::core::{
    prng::SpongosRng,
    prp::{keccak::KeccakF1600, PRP},
    spongos::Spongos,
};
