//! DDML is a data description language extended with commands for cryptographic processing.
//! DDML is implemented as an EDSL in rust.

/// DDML commands.
pub mod commands;

/// DDML command modifiers
pub mod modifiers;

/// Abstractions for input/output buffers. It does not support the actual IO.
pub mod io;

/// DDML specific types.
pub mod types;
