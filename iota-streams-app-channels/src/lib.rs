//! High-level Implementation of Streams Channel Protocol.
//!
//! API functions can be found through the [Author](api::tangle::Author) and
//! [Subscriber](api::tangle::Subscriber)
//!
//! User implementations will require a Transport
//! [Client](../iota_streams_app/transport/tangle/client/struct.Client.html)
//!
//! ## Starting a new Channel (Multi Branch)
//! ```compile fail
//! let client = Client::new_from_url("https://chrysalis-nodes.iota.org")?;
//! let author = Author::new("A Seed", "utf-8", 1024, true, client);
//!
//! let announcement_link = author.send_announce()?;
//! ```

#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// Channel Messages.
pub mod message;

/// Author and Subscriber API.
pub mod api;
