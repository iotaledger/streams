//! Stream Errors

// Rust
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::any::Any;

// 3rd-party

// IOTA

// Streams
use lets::{address::Address, id::PskId, message::Topic};

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

pub type Result2<T> = Result<T, Error>;

impl Error {
    pub(crate) fn no_cursor(topic: &Topic) -> Self {
        Self::Permission(format!(
            "user does not have a cursor in branch '{}'. This probably means the user does not have write permission over that branch",
            topic
        ))
    }

    pub(crate) fn unexpected_message_type(address: Address, message_type: u8) -> Self {
        Self::Unwrapping(
            address,
            format!(
                "unexpected message type. The message at address '{}' has an unexpected message type '{}'",
                address, message_type
            ),
        )
    }

    pub(crate) fn unwrapping<E>(message_type: &str, address: Address, error: E) -> Self
    where
        E: ToString,
    {
        Self::Unwrapping(
            address,
            format!(
                "Error unwrapping the message. The {} message at address '{}' could not be unwrapped: {}",
                message_type,
                address,
                error.to_string()
            ),
        )
    }

    pub(crate) fn not_linked(message_type: &str, address: Address) -> Self {
        Self::Unwrapping(
            address,
            format!(
                "Message not linked. The {message_type} message at address '{address}' is not linked to any message. \
Any {message_type} message must be linked to a previous message by including the address of the previous message in the header",
                message_type = message_type,
                address = address
            ),
        )
    }

    // TODO: CONSIDER MAKING IT CONST
    pub(crate) fn no_identity(op: &str) -> Self {
        Self::Fatal(format!("the user does not have an identity, but needs one to {}", op))
    }

    pub(crate) fn no_stream(op: &str) -> Self {
        Self::Setup(format!(
            "not connected to a stream. A user must either create a stream or connect to an existing one before attempting to {}",
            op
        ))
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

    pub(crate) fn unknown_psk(address: Address, pskid: PskId) -> Self {
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