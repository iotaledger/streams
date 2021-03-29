//! DDML is a data description language extended with commands for cryptographic processing.
//! DDML is implemented as an EDSL in rust.

#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// DDML command traits.
#[allow(clippy::all)]
pub mod command;

/// Abstractions for input/output buffers. It does not support the actual IO.
#[allow(clippy::all)]
pub mod io;

/// DDML specific types.
#[allow(clippy::all)]
pub mod types;

/// LinkStore trait and impls.
#[allow(clippy::all)]
pub mod link_store;
