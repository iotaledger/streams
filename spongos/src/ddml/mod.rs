//! DDML is a data description language extended with commands for cryptographic processing.
//! DDML is implemented as an EDSL in rust.

/// DDML commands.
mod commands;

/// DDML command modifiers
mod modifiers;

/// Abstractions for input/output buffers. It does not support the actual IO.
mod io;

/// DDML specific types.
mod types;

// TODO: REMOVE
// /// LinkStore trait and impls.
// #[allow(clippy::all)]
// mod link_store;
