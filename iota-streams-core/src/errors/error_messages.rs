use crate::prelude::String;
use core::fmt::Debug;
use thiserror::Error;

pub struct WrappedError<T: Debug>(pub T);

#[derive(Error, Debug)]
pub enum Errors {
    //////////
    // Generic
    //////////
    #[error("Max size exceeded (expected: {0}, found: {1})")]
    MaxSizeExceeded(usize, usize),
    #[error("Value out of range (max: {0}, index: {1})")]
    ValueOutOfRange(usize, usize),
    #[error("Value does not match (expected: {0}, found: {1})")]
    ValueMismatch(usize, usize),
    #[error("Size of vec/array does not match (expected: {0}, found: {1})")]
    LengthMismatch(usize, usize),
    #[error("Spongos is not committed, outer position is not 0")]
    SpongosNotCommitted,
    #[error("Link not found in store. (Possibly unimplemented)")]
    GenericLinkNotFound,

    //////////
    // Cryptographic
    //////////
    #[error("Failed to convert ed25519 public key to x25519 public key")]
    KeyConversionFailure,

    //////////
    // DDML Wrap/Unwrap
    //////////
    #[error("There was an issue with the calculated signature, cannot unwrap message")]
    SignatureMismatch,
    #[error("There was an issue with calculating the signature, cannot wrap message.")]
    SignatureFailure,
    #[error("Failure to generate ed25519 public key")]
    PublicKeyGenerationFailure,
    #[error("Failure to generate x25519 public key")]
    XPublicKeyGenerationFailure,
    #[error("Integrity violation. Bad MAC")]
    BadMac,
    #[error("No default Random Number Generator available for no_std usage")]
    NoStdRngMissing,

    //////////
    // DDML IO
    //////////
    #[error("Not enough space allocated for output stream (expected: {0}, found: {1})")]
    StreamAllocationExceededOut(usize, usize),
    #[error("Not enough space allocated for input stream (expected: {0}, found: {1})")]
    StreamAllocationExceededIn(usize, usize),
    #[error("Output stream has not been exhausted. Remaining: {0}")]
    OutputStreamNotFullyConsumed(usize),
    #[error("Input stream has not been exhausted. Remaining: {0}")]
    InputStreamNotFullyConsumed(usize),

    //////////
    // Generic Transport
    //////////
    #[error("More than one message found: with link {0}")]
    MessageNotUnique(String),
    #[error("Message at link {0} not found in store")]
    MessageLinkNotFound(String),
    #[error("Message at link {0} not found in tangle")]
    MessageLinkNotFoundInTangle(String),
    #[error("Transport object is already borrowed")]
    TransportNotAvailable,

    //////////
    // Iota Client
    //////////
    #[error("Iota Message Address failed to generate.")] // UNUSED
    BadTransactionAddress,
    #[error("Iota Message Tag failed to generate.")] // UNUSED
    BadTransactionTag,
    #[error("Message index not found")]
    IndexNotFound,
    #[error("Message data not found")]
    MessageContentsNotFound,
    #[error("Iota Message failed to generate.")] // UNUSED
    BadMessageTimestamp,
    #[error("Iota Message Payload failed to generate.")]
    BadMessagePayload,
    #[error("Iota Message failed to seal.")] // UNUSED
    MessageSealFailure,
    #[error("Iota Message failed to attach.")] // UNUSED
    MessageAttachFailure,
    #[error("Iota Message failed to build.")] // UNUSED
    MessageBuildFailure,
    #[error("Iota Client failed to perform operation.")]
    ClientOperationFailure,

    //////////
    // Messages
    //////////
    #[error("Message version not supported (expected: {0}, found: {1})")]
    InvalidMsgVersion(u8, u8),
    #[error("Message frame type not supported (expected: {0}, found: {1})")]
    InvalidMsgType(u8, u8),
    #[error("Message type is not known (found: {0})")]
    UnknownMsgType(u8),
    #[error("Reserved bits are improperly formatted")]
    InvalidBitReservation,
    #[error("Message is not an announcement (found: {0})")]
    NotAnnouncement(u8),
    #[error("Message info provided is not registered (found: {0})")]
    BadMessageInfo(u8),
    #[error("Failed to make message")]
    MessageCreationFailure,

    //////////
    // Users
    //////////
    #[error("Cannot create a channel, user is already registered to channel {0}")]
    ChannelCreationFailure(String),
    #[error("Cannot unwrap announcement message, already registered to channel {0}")]
    UserAlreadyRegistered(String),
    #[error("User is not registered to a channel")]
    UserNotRegistered,
    #[error("Message application instance does not match user channel (expected: {0}, found: {1}")]
    MessageAppInstMismatch(String, String),
    #[error("Author public x25519 exchange key not found in user instance")]
    AuthorExchangeKeyNotFound,
    #[error("Author public ed25519 signature key not found in user instance")]
    AuthorSigKeyNotFound,
    #[error("Error retrieving sequence number for message preparation: No sequence number generated")]
    SeqNumRetrievalFailure,
    #[error("State store has failed to retrieve")]
    StateStoreFailure,

    //////////
    // User Recovery
    //////////
    #[error("Application Instance recovery failed (expected: 0 | 1, found: {0})")]
    AppInstRecoveryFailure(u8),
    #[error("Author signature pubkey recovery failed (expected: 0 | 1, found: {0})")]
    AuthorSigPkRecoveryFailure(u8),
    #[error("User Version does not match (expected: {0}, found: {1}")]
    UserVersionRecoveryFailure(u8, u8),
    #[error("Recovered flag does not match expected: flag (expected: {0}, found: {1})")]
    UserFlagRecoveryFailure(u8, u8),

    //////////
    // Examples
    //////////
    #[error("Public Payload does not match (expected: {0}, found: {1})")]
    PublicPayloadMismatch(String, String),
    #[error("Public Payload does not match (expected: {0}, found: {1})")]
    MaskedPayloadMismatch(String, String),
    #[error("Branching flag for subscriber {0} should match authors branching flag")]
    BranchingFlagMismatch(String),
    #[error("Channel Application Instance for subscriber {0} should match authors.")]
    ApplicationInstanceMismatch(String),
    #[error("Channel Application Instance for subscriber {0} should match announcement.")]
    ApplicationInstanceAnnouncementMismatch(String),
    #[error("Subscriber {0} should not be able to access this message")]
    SubscriberAccessMismatch(String),

    //////////
    // Tests
    //////////
    #[error("Bytes are invalid. Values don't match (expected {0}, found {1}")]
    InvalidBytes(String, String),
    #[error("Squeezed tag is invalid. Unwrapped tag doesn't match (expected {0}, found {1}")]
    InvalidTagSqueeze(String, String),
    #[error("Squeezed hash is invalid. Unwrapped hash doesn't match (expected {0}, found {1}")]
    InvalidHashSqueeze(String, String),
    #[error("Squeezed key is invalid. Unwrapped key doesn't match (expected {0}, found {1}")]
    InvalidKeySqueeze(String, String),
    #[error("Subscriber {0} failed to unwrap message, may not have access to branch")]
    MessageUnwrapFailure(String),
}
