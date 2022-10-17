//! # LETS
//! The `lets` crate houses message-oriented cryptographic protocols. Identification, transportation
//! and generic message handling protocols in these modules can be used to build streaming
//! applications. Signature and encryption operations are handled via the `id` module, while
//! `message` encoding operations are managed via the `message` module. Messages are indexed by an
//! `Address` composed of an `Application Address` and `Message Identifier`, and the library
//! provides a `Transport` trait to allow for agnostic transport client creation.
//!
//! A Streams Message must contain an `HDF` (Header) and `PCF` (Payload), and must be declared in
//! `DDML` syntax in order to be processed correctly. Message internal processes follow `DDML`
//! rules.

#![allow(clippy::module_inception)]
#![no_std]

#[macro_use]
extern crate alloc;

// Uncomment to enable printing for development
// #[macro_use]
// extern crate std;

/// Message definitions and utils for wrapping/unwrapping.
pub mod message;

/// Message addressing and linking
pub mod address;

/// Transport-related abstractions.
pub mod transport;

/// Identity based Signature/Verification utilities
pub mod id;

/// Errors specific for LETS
pub mod error;
