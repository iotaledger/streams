//! Stream Errors

// Rust
use core::{array::TryFromSliceError, fmt::Debug};

// 3rd-party
use thiserror_no_std::Error;
// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    error::Error as LetsError,
    id::{Identifier, PskId},
    message::{Topic, TopicHash},
};

use spongos::error::Error as SpongosError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
/// Error type of the streams crate.
#[allow(clippy::large_enum_variant)]
pub enum Error {
    //////////
    // Streams
    //////////
    #[error(
        "Address already taken. The address '{1}' where the {0} message is being sent already contains some data, possibly spam."
    )]
    AddressUsed(&'static str, Address),

    #[error("Unexpected message type {0}")]
    MessageTypeUnknown(u8),

    #[error("Message  '{0}' not found in {1}")]
    MessageMissing(MsgId, &'static str),

    #[error("Failed to get messages. Error: {0}")]
    Messages(anyhow::Error),

    #[error(
        "User does not have a cursor stored in branch '{0}'. This probably means the user does not have write permission within that branch"
    )]
    NoCursor(Topic),

    #[error("User does not have an identity, but needs one to {0}")]
    NoIdentity(&'static str),

    #[error("User identity contains no secret key")]
    NoSecretKey,

    #[error(
        "Not connected to a stream. A user must either create a stream or connect to an existing one before attempting to {0}"
    )]
    NoStream(&'static str),

    #[error(
        "Message not linked. The {0} message at address '{1:#?}' is not linked to a previous message. \
Any {0} message must be linked to a previous message by including the address of the existing message in the header"
    )]
    NotLinked(&'static str, Address),

    #[error("A payload must be specified in order to send a message")]
    PayloadEmpty,

    #[error("Setup error: {0}")]
    Setup(&'static str),

    #[error("Topic {0} not found in store")]
    TopicNotFound(Topic),

    #[error("Transport error while trying to {1} for address {0}; Error: {2}")]
    Transport(Address, &'static str, LetsError),

    #[error("PSK by id {0} is not known")]
    UnknownPsk(PskId),

    #[error("Topic by hash {0} is not known")]
    UnknownTopic(TopicHash),

    #[error("Error unwrapping the message {0}. The message at address '{1:#?}' could not be unwrapped: {2}")]
    Unwrapping(&'static str, Address, LetsError),

    #[error("Missing role {0} for {1:?} in order to {2}")]
    WrongRole(&'static str, Identifier, &'static str),

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

    #[error("External error: {0:?}")]
    External(anyhow::Error),

    /// TODO REMOVE or merge
    #[error("Internal error {0} Cause: {1}")]
    Wrapped(&'static str, lets::error::Error),
}

impl From<SpongosError> for Error {
    fn from(error: SpongosError) -> Self {
        Self::Spongos(error)
    }
}

// Merge with Lets errors?

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Self::External(error.into())
    }
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Self::External(error)
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for Error {}
