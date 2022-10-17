//! # Spongos
//! The Spongos crate houses core functionality for `DDML` and sponge based cryptographic
//! operations. The core module houses trait bounds for `Pseudo-Random Permutation` instances (the
//! default implementation used in this library is `Keccak-f[1600]`), as well as the custom
//! `Spongos` wrapper, which makes up the foundation of state management and `DDML` command
//! operations. The ddml module houses `Spongos` based commands for
//! encoding/decoding/encryption/signature functionality.

#![no_std]

// Spongos requires heap allocation for Vectors and Strings
#[cfg_attr(all(test, not(feature = "std")), macro_use)]
extern crate alloc;

// Spongos requires the feature "std" for the Dump DDML command
#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod error;
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
