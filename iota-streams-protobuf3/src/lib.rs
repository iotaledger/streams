//! Protobuf3 is trinary data description language extended with commands for cryptographic processing.
//! Protobuf3 is implemented as a EDSL in rust.

/// Protobuf3 command traits.
pub mod command;

/// Abstractions for input/output buffers. It does not support the actual IO.
pub mod io;

/// Protobuf3 specific types.
pub mod types;
