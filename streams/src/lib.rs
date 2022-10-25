//! High-level Implementation of Streams Channel Protocol.
//!
//! API functions can be found through the [`User`]
//!
//! User implementations will require a Transport
//! [Client](`lets::transport::utangle::Client`)
//!
//! ## Starting a new Channel
//! ```
//! use streams::{
//!     transport::utangle,
//!     id::Ed25519,
//!     User, Result
//! };
//! # use streams::transport::bucket;
//! #[tokio::main]
//! async fn main() -> Result<()> {
//! let transport: utangle::Client = utangle::Client::new("https://chrysalis-nodes.iota.org");
//! # let test_transport = bucket::Client::new();
//! let mut author = User::builder()
//!     .with_identity(Ed25519::from_seed("A cryptographically secure seed"))
//!     .with_transport(transport)
//! #     .with_transport(test_transport)
//!     .build();
//!
//! let announcement = author.create_stream("BASE_BRANCH").await?;
//! # Ok(())
//! # }
//! ```

#![no_std]

// Uncomment to enable printing for development
// #[macro_use]
// extern crate std;

#[macro_use]
extern crate alloc;

/// Protocol message types and encodings
mod message;

/// [`User`] API.
mod api;

pub use api::{
    message::{Message, MessageContent},
    message_builder::MessageBuilder,
    messages::Messages,
    selector::Selector,
    send_response::SendResponse,
    user::User,
    user_builder::UserBuilder,
};

/// Errors for Streams
mod error;
pub use error::{Error, Result};

pub use lets::{address::Address, id, message::TransportMessage, transport};
