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
/// Error type of the iota client crate.
#[allow(clippy::large_enum_variant)]
/// #[serde(tag = "type", content = "error")]
pub enum Error {
    //////////
    // Streams
    //////////
    #[error("the user does not have an identity, but needs one to {0}")]
    NoIdentity(&'static str),

    #[error("User identity contained no secret key")]
    NoSecretKey,

    #[error("Missing {0} for {1} in order to {2}")]
    MissingUserData(&'static str, &'static str, &'static str),

    #[error("Missing role {0} for {1:?} in order to {2}")]
    WrongRole(&'static str, Identifier, &'static str),

    #[error(
        "user does not have a cursor in branch '{0}'. This probably means the user does not have write permission over that branch"
    )]
    NoCursor(Topic),

    #[error("topic {0} not found in store")]
    TopicNotFound(Topic),

    #[error("Topic by hash {0} is not known")]
    UnknownTopic(TopicHash),

    #[error("PSK by id {0} is not known")]
    UnknownPsk(PskId),

    #[error("A payload must be specified in order to send a message")]
    PayloadEmpty,

    #[error("unexpected message type {0}")]
    MessageTypeUnknown(u8),

    #[error("message '{0}' not found in {1}")]
    MessageMissing(MsgId, &'static str),

    #[error("Error unwrapping the message {0}. The message at address '{1:#?}' could not be unwrapped: {2}")]
    Unwrapping(&'static str, Address, LetsError),

    #[error(
        "Message not linked. The {0} message at address '{1:#?}' is not linked to any message. \
Any {0} message must be linked to a previous message by including the address of the previous message in the header"
    )]
    NotLinked(&'static str, Address),

    #[error(
        "not connected to a stream. A user must either create a stream or connect to an existing one before attempting to {0}"
    )]
    NoStream(&'static str),

    #[error("Setup error: {0}")]
    Setup(&'static str),

    #[error("Transport error whilest doing {0} for address {1}: {2}")]
    Transport(Address, &'static str, LetsError),

    #[error("Failed getting messages for {0} due to {1}")]
    Messages(&'static str, anyhow::Error),

    #[error(
        "address already taken for. The address '{1}' where the {0} message is being sent already contains some data, possibly spam."
    )]
    AddressUsed(&'static str, Address),

    /// TODO REMOVE
    #[error("Internal error {0} Cause: {1}")]
    Wrapped(&'static str, lets::error::Error),

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

    #[error("Internal LETS error: {0}")]
    Lets(LetsError),

    #[error("External error: {0:?}")]
    External(anyhow::Error),
}

impl From<SpongosError> for Error {
    fn from(error: SpongosError) -> Self {
        Self::Spongos(error)
    }
}

impl From<LetsError> for Error {
    fn from(error: LetsError) -> Self {
        Self::Lets(error)
    }
}

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

