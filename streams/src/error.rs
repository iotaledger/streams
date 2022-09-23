//! Stream Errors

// Rust
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::fmt::{Debug, Display};

// 3rd-party
use serde::{ser::Serializer, Serialize};

// IOTA

// Streams
use lets::{address::Address, id::{PskId, Identifier}, message::{Topic, TopicHash}};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, Serialize)]
/// Error type of the iota client crate.
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type", content = "error")]
pub enum Error {
    //////////
    // Streams
    //////////
    #[error("message payload cannot be empty")]
    PayloadEmpty,

    #[error("the user does not have an identity, but needs one to {0}")]
    NoIdentity(String),

    #[error("Missing role {0} for {1} in order to {2}")]
    WrongRole(String, Identifier, String),

    #[error("user does not have a cursor in branch '{}'. This probably means the user does not have write permission over that branch")]
    NoCursor(Topic),

    #[error("previous topic {0} not found in store")]
    PreviousTopicNotFound(Topic),

    #[error("unexpected message type {0}")]
    MessageTypeUnknown(u8),

    #[error("Error unwrapping the message {0}. The message at address '{2}' could not be unwrapped: {3}")]
    Unwrapping(String, Address, anyhow::Error),

    #[error("Error unwrapping the message {0}. The message at address '{2}' could not be unwrapped: {3}")]
    UnknownTopic(TopicHash),

    #[error("Message not linked. The {0} message at address '{1}' is not linked to any message. \
Any {0} message must be linked to a previous message by including the address of the previous message in the header")]
    NotLinked(String, Address),

    #[error("User identity contained no secret key")]
    NoSecretKey,
    
    #[error("not connected to a stream. A user must either create a stream or connect to an existing one before attempting to {0}")]
    NoStream(String),

    /*#[error("branch announcement received from user that is not stored as a publisher")]
    UnknownTopic(TopicHash),*/

    #[error("{0}")]
    #[serde(serialize_with = "display_string")]
    Other(Address),

    /// Error when building tagged_data blocks
    #[error("Internal error {0} Cause: {1}")]
    Wrapped(String, Box<Error>),

    /*
    //////////
    // Generic
    //////////
    /// Max size exceeded (expected: {0}, found: {1})
    MaxSizeExceeded(usize, usize),
    /// Value out of range (max: {0}, index: {1})
    ValueOutOfRange(usize, usize),
    /// Value does not match (expected: {0}, found: {1})
    ValueMismatch(usize, usize),
    /// Size of vec/array does not match (expected: {0}, found: {1})
    LengthMismatch(usize, usize),
    /// Spongos is not committed, outer position is not 0
    SpongosNotCommitted,
    /// Link not found in store. (Possibly unimplemented)
    GenericLinkNotFound,
    /// Unexpected/invalid Identifier
    BadIdentifier,
    /// Psk has already been stored
    PskAlreadyStored,
    /// Input string {0} is not in hex format
    BadHexFormat(String),

    //////////
    // Cryptographic
    //////////
    /// Failed to convert ed25519 public key to x25519 public key
    KeyConversionFailure,

    //////////
    // DDML Wrap/Unwrap
    //////////
    /// There was an issue with the calculated signature, cannot unwrap message
    SignatureMismatch,
    /// There was an issue with calculating the signature, cannot wrap message.
    SignatureFailure,
    /// Failure to generate ed25519 public key
    PublicKeyGenerationFailure,
    /// Failure to generate x25519 public key
    XPublicKeyGenerationFailure,
    /// Integrity violation. Bad MAC
    BadMac,
    /// No default Random Number Generator available for no_std usage
    NoStdRngMissing,
    /// Oneof value is unexpected
    BadOneof,

    //////////
    // DDML IO
    //////////
    /// Not enough space allocated for output stream (expected: {0}, found: {1})
    StreamAllocationExceededOut(usize, usize),
    /// Not enough space allocated for input stream (expected: {0}, found: {1})
    StreamAllocationExceededIn(usize, usize),
    /// Output stream has not been exhausted. Remaining: {0}
    OutputStreamNotFullyConsumed(usize),
    /// Input stream has not been exhausted. Remaining: {0}
    InputStreamNotFullyConsumed(usize),

    //////////
    // Generic Transport
    //////////
    /// More than one message found: with link {0}
    MessageNotUnique(String),
    /// Message at link {0} not found in state store
    MessageLinkNotFoundInStore(String),
    /// Message at link {0} not found in Tangle
    MessageLinkNotFoundInTangle(String),
    /// Message at link {0} not found in Bucket transport
    MessageLinkNotFoundInBucket(String),
    /// Transport object is already borrowed
    TransportNotAvailable,

    //////////
    // Iota Transport
    //////////
    /// Malformed address string: missing colon (':') separator between appinst and msgid
    MalformedAddressString,
    /// Invalid Message Address
    InvalidMessageAddress,
    /// Invalid Channel Address
    InvalidChannelAddress,
    /// Invalid Msg id
    InvalidMsgId,

    //////////
    // Iota Client
    //////////
    /// Iota Message Address failed to generate. // UNUSED
    BadTransactionAddress,
    /// Iota Message Tag failed to generate. // UNUSED
    BadTransactionTag,
    /// Message index not found
    IndexNotFound,
    /// Message data not found
    MessageContentsNotFound,
    /// Iota Message failed to generate. // UNUSED
    BadMessageTimestamp,
    /// Iota Message Payload failed to generate.
    BadMessagePayload,
    /// Iota Message failed to seal. // UNUSED
    MessageSealFailure,
    /// Iota Message failed to attach. // UNUSED
    MessageAttachFailure,
    /// Iota Message failed to build. // UNUSED
    MessageBuildFailure,
    /// Iota Client failed to perform operation.
    ClientOperationFailure,

    //////////
    // Messages
    //////////
    /// Message version not supported (expected: {0}, found: {1})
    InvalidMsgVersion(u8, u8),
    /// Message frame type not supported (expected: {0}, found: {1})
    InvalidMsgType(u8, u8),
    /// Message type is not known (found: {0})
    UnknownMsgType(u8),
    /// Reserved bits are improperly formatted
    InvalidBitReservation,
    /// Message is not an announcement (found: {0})
    NotAnnouncement(u8),
    /// Message info provided is not registered (found: {0})
    BadMessageInfo(u8),
    /// Failed to make message
    MessageCreationFailure,
    /// Identifier could not be generated with given bytes. Must be an ed25519 Public Key or a PskId
    IdentifierGenerationFailure,

    //////////
    // Users
    //////////
    /// Cannot create a channel, user is already registered to channel {0}
    ChannelCreationFailure(String),
    /// Cannot register new user {0}, user is already registered to channel {1}
    UserAlreadyRegistered(String, String),
    /// User is not registered to a channel
    UserNotRegistered,
    /// Message application instance does not match user channel (expected: {0}, found: {1}
    MessageAppInstMismatch(String, String),
    /// Author public x25519 exchange key not found in user instance
    AuthorExchangeKeyNotFound,
    /// Author public ed25519 signature key not found in user instance
    AuthorSigKeyNotFound,
    /// Error retrieving sequence number for message preparation: No sequence number generated
    SeqNumRetrievalFailure,
    /// State store has failed to retrieve
    StateStoreFailure,
    /// Cannot generate new channel, it may already exists. please try using a different seed
    ChannelDuplication,
    /// Subscriber already has a psk stored, cannot add another
    SinglePskAllowance,
    /// Subscriber send operations are not allowed in Single Depth mode
    SingleDepthOperationFailure,
    /// Operation only available on single depth channels
    ChannelNotSingleDepth,
    /// Message '{0}' does not have a previous message
    NoPreviousMessage(String),

    //////////
    // User Recovery
    //////////
    /// Application Instance recovery failed (expected: 0 | 1, found: {0})
    AppInstRecoveryFailure(u8),
    /// Author signature pubkey recovery failed (expected: 0 | 1, found: {0})
    AuthorSigPkRecoveryFailure(u8),
    /// User Version does not match (expected: {0}, found: {1}
    UserVersionRecoveryFailure(u8, u8),
    /// Recovered flag does not match expected: flag (expected: {0}, found: {1})
    UserFlagRecoveryFailure(u8, u8), */
}

/// Use this to serialize Error variants that implements Debug but not Serialize
fn display_string<T, S>(value: &T, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    T: Display,
    S: Serializer,
{
    value.to_string().serialize(serializer)
}

/*

// Local

/// Streams `Error`
///
/// This enum includes all possible errors returned by the fallible operations of this library.
/// The errors have been classified according to the different business logic that they are expected
/// to trigger:
/// - `Transport`: the transport layer has experienced a temporary malfunction. The operation can be
///   attempted again as is once the transport layer recovers
/// - `Data`: the data provided by the user involved in the operation is invalid. The operation can
///   be attempted again once the data has been corrected
/// - `Setup`: the environment in which the operation is being performed is incorrect. The operation
///   can be attempted again once the environment has been ammended
/// - `Permission`: the user does not have permission to perform the operation. The operation should
///   not be attempted again unless the permissions of the user change
/// - `MessageNotFound`: the message being fetched has not been found by the transport layer. The
///   operation might be attempted again after a while to check if the message has been published
/// - `Fatal`: the user is attempting an impossible operation and should desist from it.
/// - `Unwrapping`: the user is attempting to unwrap an invalid message. Spam messages would fall
///   into this error, so this kind of error should be logged carefully.
/// - `CacheMiss`: the message could not be wrapped or unwrapped because the Spongos state of the
///   message it is linked to cannot be found in the cache. The operation can be attempted again as
///   is once the linked message is fetched
#[derive(Debug)]
pub enum Error {
    // TODO: REVISIT dyn Any (alternative: Generic E given by user, linked to the error of transport layer)
    Transport(Address, Box<dyn Any + Send + Sync>, &'static str),
    Data(Address, String),
    Setup(String),
    Permission(String),
    MessageNotFound,
    // TODO: CONSOLIDATE WITH MESSAGE::ORPHAN
    CacheMiss(Address, Address, String),
    Unwrapping(Address, String),
    Fatal(String),
}

    pub(crate) fn transport(op: &'static str, address: Address, error: Box<dyn Any + Send + Sync>) -> Self {
        Self::Transport(address, error, op)
    }

    pub(crate) fn topic_already_used(topic: Topic, address: Address) -> Self {
        Self::Data(
            address,
            format!(
                "stream topic already used. There already is an stream created by this user with the topic '{}' in address '{}'. Either connect to it, or use a different topic",
                topic, address
            ),
        )
    }

    pub(crate) fn address_taken(message_type: &str, address: Address) -> Self {
        Self::Fatal(format!(
            "address already taken. The address '{}' where the {} message is being sent already contains some data, possibly spam",
            address, message_type
        ))
    }

    pub(crate) fn wrapping<E>(message_type: &str, topic: &Topic, address: Address, error: E) -> Self
    where
        E: ToString,
    {
        Self::Data(
            address,
            format!(
                "Error wrapping the message. The {} message being sent at topic '{}' (address '{}') could not be wrapped: {}",
                message_type,
                topic,
                address,
                error.to_string()
            ),
        )
    }

    pub(crate) fn linked_not_in_store(message_type: &str, topic: &Topic, address: Address, linked: Address) -> Self {
        Self::CacheMiss(
            address,
            linked,
            format!(
                "linked message not found in store. The message being sent at topic '{}' (address '{}') is linked to the message with address '{}', \
but the Spongos state of this linked message cannot be found in the Spongos store. In order to send the message, \
first fetch the linked message to load it to the store",
                topic, address, linked
            ),
        )
    }

    pub(crate) fn unknown_psk(address: &Address, pskid: &PskId) -> Self {
        Self::Data(
            address,
            format!(
                "unknown PSK. The PSK '{pskid}' is not found in the PSK store. To send the keyload message (meant for address '{address}') either remove \
'{pskid}' from the list of PskIds or add the PSK to the user instance",
                pskid = pskid,
                address = address,
            ),
        )
    }
}

macro_rules! unwrap_or_return {
    (e) => {};
}
*/