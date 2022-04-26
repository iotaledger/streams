//! High-level Implementation of Streams Channel Protocol.
//!
//! API functions can be found through the [User](api::tangle::User)
//!
//! User implementations will require a Transport
//! [Client](../iota_streams_app/transport/tangle/client/struct.Client.html)
//!
//! ## Starting a new Channel
//! ```no_run
//! let client = Client::new_from_url("https://chrysalis-nodes.iota.org")?;
//! let author = UserBuilder::new()
//!     .with_identity(UserIdentity::new("A Seed"))
//!     .with_transport(client)
//!     .build()?;
//!
//! let announcement_link = author.send_announce()?;
//! ```

#![no_std]

// #[cfg(feature = "std")]
// #[macro_use]
// extern crate std;

#[macro_use]
extern crate alloc;

/// Protocol message types and encodings
mod message;

/// [`User`] API.
mod api;

// /// Get a `Value` given a `Key`
// ///
// /// This trait can be implemented to any kind of collection to get an item out of it.
// /// It's meant to be versatile, so it can be implemented for T or &T, and both `Key` and
// /// `Value` can be owned or references as well.
// trait Lookup<Key, Value> {
//     fn lookup(&self, key: Key) -> Option<Value>;
// }

// // Reexport the most frequently used types for an easier discoverability
// #[cfg(feature = "tangle")]
// use api::{
//     Address,
//     MessageContent,
//     UnwrappedMessage,
//     User,
//     UserBuilder,
// };

// #[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
// use LETS::transport::tangle::client::Client as Tangle;

// // TODO: REMOVE BYTES DEPENDENCY ALLTOGETHER
// use iota_streams_ddml::types::Bytes;

// use iota_streams_app::id::UserIdentity;
