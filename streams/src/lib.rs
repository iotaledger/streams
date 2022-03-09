//! IOTA-Streams Client
//!
//! API functions can be found through the [Author](api::tangle::Author) and
//! [Subscriber](api::tangle::Subscriber)
#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// Protocol message types and encodings
mod message;

/// Author and Subscriber API.
mod api;

/// Get a `Value` given a `Key`
///
/// This trait can be implemented to any kind of collection to get an item out of it.
/// It's meant to be versatile, so it can be implemented for T or &T, and both `Key` and
/// `Value` can be owned or references as well.
trait Lookup<Key, Value> {
    fn lookup(&self, key: Key) -> Option<Value>;
}

#[cfg(feature = "duh")]
pub use api::tangle::{
    Address,
    Author,
    ChannelType,
    MessageContent,
    Subscriber,
    UnwrappedMessage,
};
#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
pub use lets::transport::tangle::client::Client as Tangle;

// TODO: REMOVE BYTES DEPENDENCY ALLTOGETHER
pub use spongos::types::Bytes;
