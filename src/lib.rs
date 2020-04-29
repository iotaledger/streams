//! A cryptographic framework for building secure messaging applications
//!
//! This top-level crate contains references to the others that make up
//! the IOTA Streams framework.
//!
//! # Layout
//!
//! This framework is divided into the following crates:
//! - `iota_streams_app_channels`: An API for using
//! the built-in Channels application
//! - `iota_streams_app`: The `message` and `transport` modules
//! for creating your own Streams applications
//! - `iota_streams_core`: Modules for the core cryptographic features used by Streams,
//! including ternary to binary conversions
//! - `iota_streams_core_keccak`: Modules for using sponge constructions with KeccakF1600B
//! and KeccakF1600T permutations
//! - `iota_streams_core_merkletree`: A module for working with traversable Merkle trees
//! - `iota_streams_core_mss`: Modules for validating Merkle tree signatures
//! and generating private keys, public keys and signatures with the Winternitz one-time signature scheme
//! - `iota_streams_core_ntru`:  A module for working with NTRU key pairs
//! - `iota_streams_protobuf3`: Modules for working with
//! the IOTA trinary data description language called Protobuf3, in which all Streams messages are encoded

pub use iota_streams_app_channels as app_channels;
pub use iota_streams_app as app;
pub use iota_streams_core as core;
pub use iota_streams_core_keccak as core_keccak;
pub use iota_streams_core_merkletree as core_merkletree;
pub use iota_streams_core_mss as core_mss;
pub use iota_streams_core_ntru as core_ntru;
pub use iota_streams_protobuf3 as protobuf3;