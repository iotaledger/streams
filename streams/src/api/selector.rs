// Rust
use core::{fmt::Formatter, ops::Range};

// IOTA

// Streams
use lets::{address::Address, id::Identifier, message::TopicHash};

use crate::Message;

/// An enum that is used to select messages from a stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Selector {
    Address(Address),
    Topic(TopicHash),
    Identifier(Identifier),
    Level(Range<usize>),
}

impl Selector {
    /// > If the selector is an address, check if the message address is equal to the selector
    /// > address.
    /// If the selector is a topic, check if the message topic is equal to the selector topic. If
    /// the selector is an identifier, check if the message publisher is equal to the selector
    /// identifier. If the selector is a level, check if the message sequence is contained in
    /// the selector level
    ///
    /// # Arguments
    ///
    /// * `message`: The message to check against the selector.
    ///
    /// Returns:
    ///
    /// A boolean value.
    pub fn is(&self, message: &Message) -> bool {
        match self {
            Selector::Address(address) => &message.address == address,
            Selector::Topic(topic) => message.header().topic_hash() == topic,
            Selector::Identifier(identifier) => message.header().publisher() == identifier,
            Selector::Level(range) => range.contains(&message.header().sequence()),
        }
    }
}

impl core::fmt::Display for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", &self)
    }
}
