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

// Uncomment to enable printing for development
// #[macro_use]
// extern crate std;

extern crate alloc;

/// Protocol message types and encodings
mod message;

/// [`User`] API.
mod api;

// // Reexport the most frequently used types for an easier discoverability
// #[cfg(feature = "tangle")]
// use api::{
//     Address,
//     MessageContent,
//     UnwrappedMessage,
//     User,
//     UserBuilder,
// };

pub use api::{
    message::Message,
    send_response::SendResponse,
    user::User,
};
pub use LETS::{
    id,
    link::Address,
    transport,
};

// // TODO: REMOVE BYTES DEPENDENCY ALLTOGETHER
// use iota_streams_ddml::types::Bytes;

// use iota_streams_app::id::UserIdentity;
