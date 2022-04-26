// Rust
use core::fmt::Display;
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    vec::Vec,
};

// 3rd-party
use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;

// IOTA

// Streams

// Local
use crate::{
    link::Addressable,
    transport::Transport,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BucketTransport<Address, Msg> {
    // Use BTreeMap instead of HashMap to make BucketTransport nostd without pulling hashbrown
    // (this transport is for hacking purposes only, performance is no concern)
    bucket: BTreeMap<Address, Vec<Msg>>,
}

impl<Link, Msg> BucketTransport<Link, Msg>
// where
//     Link: Eq + hash::Hash,
{
    fn new() -> Self {
        Self::default()
    }
}

impl<Link, Msg> Default for BucketTransport<Link, Msg> {
    // Implement default manually because derive puts Default bounds in type parameters
    fn default() -> Self {
        Self {
            bucket: BTreeMap::default(),
        }
    }
}

#[async_trait(?Send)]
impl<Address, Msg> Transport<Address, Msg, Msg> for BucketTransport<Address, Msg>
where
    Address: Ord + Display,
    Msg: Clone,
     /* where
                                *     Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync +
                                * core::fmt::Display,     Msg: LinkedMessage<Link> +
                                * Clone + core::marker::Send + core::marker::Sync, */
{
    async fn send_message(&mut self, addr: Address, msg: Msg) -> Result<Msg> {
        self.bucket.entry(addr).or_default().push(msg.clone());
        Ok(msg)
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Msg>> {
        self.bucket
            .get(&address)
            .cloned()
            .ok_or_else(|| anyhow!("No messages found at address {}", address))
    }

    // TODO: REMOVE
    // async fn recv_message(&mut self, address: &'a Address) -> Result<Msg> {
    //     let mut msgs = self.recv_messages(address).await?;
    //     if let Some(msg) = msgs.pop() {
    //         ensure!(msgs.is_empty(), "More than one message found: with address {}", address);
    //         Ok(msg)
    //     } else {
    //         Err(anyhow!("Message at link {} not found in Bucket transport", address))
    //     }
    // }
}
