// Rust
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    vec::Vec,
};

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;

// IOTA

// Streams

// Local
use crate::{
    address::Address,
    message::TransportMessage,
    transport::Transport,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Client<Msg = TransportMessage> {
    // Use BTreeMap instead of HashMap to make BucketTransport nostd without pulling hashbrown
    // (this transport is for hacking purposes only, performance is no concern)
    bucket: BTreeMap<Address, Vec<Msg>>,
}

impl<Msg> Client<Msg> {
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
    async fn send_message(&mut self, addr: Address, msg: Msg) -> Result<Msg>
    where
        Self::Msg: 'async_trait,
    {
        self.bucket.entry(addr).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Msg>> {
        self.bucket
            .get(&address)
            .cloned()
            .ok_or_else(|| anyhow!("No messages found at address {}", address))
    }
}
