// Rust
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams

// Local
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};

/// [`BTreeMap`] wrapper client for testing purposes
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Client<Msg = TransportMessage> {
    /// Mapping of stored [Addresses](`Address`) and `Messages`
    // Use BTreeMap instead of HashMap to make BucketTransport nostd without pulling hashbrown
    // (this transport is for hacking purposes only, performance is no concern)
    bucket: BTreeMap<Address, Vec<Msg>>,
}

impl<Msg> Client<Msg> {
    /// Creates a new [Bucket Client](`Client`)
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Msg> Default for Client<Msg> {
    // Implement default manually because derive puts Default bounds in type parameters
    fn default() -> Self {
        Self {
            bucket: BTreeMap::default(),
        }
    }
}

#[async_trait(?Send)]
impl<Msg> Transport<'_> for Client<Msg>
where
    Msg: Clone,
{
    type Msg = Msg;
    type SendResponse = Msg;

    /// If the address is not in the bucket, add it and return the message.
    ///
    /// # Arguments
    /// * `addr`: Address - The address of the message to store.
    /// * `msg`: The message to store.
    ///
    /// Returns:
    /// The message that was sent.
    async fn send_message(&mut self, addr: Address, msg: Msg) -> Result<Msg>
    where
        Self::Msg: 'async_trait,
    {
        self.bucket.entry(addr).or_default().push(msg.clone());
        Ok(msg)
    }

    /// Returns a vector of messages from the bucket, or an error if the bucket doesn't contain the
    /// address
    ///
    /// # Arguments
    /// * `address`: The address to retrieve messages from.
    ///
    /// Returns:
    /// A vector of messages.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Msg>> {
        self.bucket
            .get(&address)
            .cloned()
            .ok_or(Error::AddressError("No message found", address))
    }
}
