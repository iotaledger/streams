// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};
use core::fmt::Display;

// 3rd-party
use anyhow::{
    ensure,
    Result,
};
use async_trait::async_trait;
use futures::{
    future::{
        join_all,
        try_join_all,
    },
    TryFutureExt,
};

// IOTA
use iota_client::bee_message::Message as IotaMessage;

// Streams

// Local
use crate::{
    link::Address,
    transport::Transport,
};

#[derive(Debug)]
/// Stub type for iota_client::Client.  Removed: Copy, Default, Clone
struct Client(iota_client::Client);

impl Client {
    // Create an instance of Client with a ready client and its send options
    fn new(client: iota_client::Client) -> Self {
        Self(client)
    }

    // Shortcut to create an instance of Client connecting to a node with default parameters
    async fn for_node(node_url: &str) -> Result<Self> {
        Ok(Self(
            iota_client::ClientBuilder::new()
                .with_node(node_url)?
                .with_local_pow(false)
                .finish()
                .await?,
        ))
    }

    fn client(&self) -> &iota_client::Client {
        &self.0
    }

    fn client_mut(&mut self) -> &mut iota_client::Client {
        &mut self.0
    }
}

#[async_trait(?Send)]
impl<Message> Transport<Address, Message, Message> for Client
where
    Message: Into<Vec<u8>> + From<IotaMessage>,
{
    async fn send_message(&mut self, address: Address, msg: Message) -> Result<Message>
    where
        Message: 'async_trait,
    {
        Ok(self
            .client()
            .message()
            .with_index(address.to_blake2b())
            .with_data(msg.into())
            .finish()
            .await?
            .into())
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Message>> {
        let msg_ids = self.client().get_message().index(address.to_blake2b()).await?;
        ensure!(!msg_ids.is_empty(), "no message found at index '{}'", address);

        let msgs = try_join_all(
            msg_ids
                .iter()
                .map(|msg| self.client().get_message().data(msg).map_ok(Into::into)),
        )
        .await?;
        Ok(msgs)
    }
}
