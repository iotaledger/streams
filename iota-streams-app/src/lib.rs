//! IOTA Streams Application layer: core definitions and Channel Application.
//!
//! # Streams Application
//! Streams Application is a message-oriented cryptographic protocol. Application
//! defines protocol parties, their roles, syntax and semantic of protocol messages.
//! Messages are declared in DDML syntax and are processed according to
//! DDML rules. Streams Message consists of Header and Application-specific Content.
//!
//! # Channel Application
//! Channel Application has evolved from previous versions of Streams. There are two
//! roles: Author and Subscriber. Author is a channel instance owner capable of
//! proving her identity by signing messages. Subscribers in this sense are anonymous
//! as their public identity (Ed25519 public key) are not revealed publicly.
//! Author can share session key information (Keyload) with a set of Subscribers.
//! Author as well as allowed Subscribers can then interact privately and securely.
//!
//! # Customization
//! There are a few known issues that arise in practice. Streams v1.1 makes an attempt
//! at tackling them by tweaking run-time and compile-time parameters. If Channel
//! Application is not suitable for your needs you can implement your own Application,
//! and DDML implementation as a EDSL allows you to easily wrap and unwrap
//! messages of your Application. And when DDML is not powerful enough,
//! it can be extended with custom commands.

#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// Streams Message definitions and utils for wrapping/unwrapping.
pub mod message;

/// Transport-related abstractions.
pub mod transport;

pub use cstr_core;
pub use cty;
// pub trait TrustProvider<PublicKey> {
// fn check_trusted(pk: &PublicKey) -> Result<()>;
// }
