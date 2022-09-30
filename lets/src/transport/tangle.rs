// Rust
use alloc::{boxed::Box, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

// 3rd-party
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use futures::{
    future::{ready, try_join_all},
    TryFutureExt,
};

// IOTA
use iota_client::bee_message::{payload::Payload, Message as IotaMessage};

// Streams

// Local
use crate::{address::Address, message::TransportMessage, transport::Transport};

/// A [`Transport`] Client for sending and retrieving binary messages from an `IOTA Tangle` node.
/// This Client uses the [iota.rs](`https://github.com/iotaledger/iota.rs`) Client implementation.
#[derive(Debug)]
pub struct Client<Message = TransportMessage, SendResponse = TransportMessage>(
    iota_client::Client,
    PhantomData<(Message, SendResponse)>,
);

impl<Message, SendResponse> Client<Message, SendResponse> {
    /// Create an instance of [`Client`] with an  explicit client
    pub fn new(client: iota_client::Client) -> Self {
        Self(client, PhantomData)
    }

    /// Shortcut to create an instance of [`Client`] connecting to a node with default parameters
    ///
    /// # Arguments
    /// * `node_url`: URL endpoint for node operations
    pub async fn for_node(node_url: &str) -> Result<Client<Message, SendResponse>> {
        Ok(Self(
            iota_client::ClientBuilder::new()
                .with_node(node_url)?
                .with_local_pow(true)
                .finish()
                .await?,
            PhantomData,
        ))
    }

    /// Returns a reference to the `IOTA` [Client](`iota_client::Client`)
    pub fn client(&self) -> &iota_client::Client {
        &self.0
    }

    /// Returns a mutable reference to the `IOTA` [Client](`iota_client::Client`)
    pub fn client_mut(&mut self) -> &mut iota_client::Client {
        &mut self.0
    }
}

#[async_trait(?Send)]
impl<Message, SendResponse> Transport<'_> for Client<Message, SendResponse>
where
    Message: Into<Vec<u8>> + TryFrom<IotaMessage, Error = anyhow::Error>,
    SendResponse: TryFrom<IotaMessage, Error = anyhow::Error>,
{
    type Msg = Message;
    type SendResponse = SendResponse;

    /// Sends a message indexed at the provided [`Address`] to the tangle.
    ///
    /// Arguments:
    /// * `address`: The address of the message to send.
    /// * `msg`: Message - The message to send.
    async fn send_message(&mut self, address: Address, msg: Message) -> Result<SendResponse>
    where
        Message: 'async_trait,
    {
        self.client()
            .message()
            .with_index(address.to_msg_index())
            .with_data(msg.into())
            .finish()
            .await?
            .try_into()
    }

    /// Retrieves a message indexed at the provided [`Address`] from the tangle. Errors if no messages
    /// are found.
    ///
    /// Arguments:
    /// * `address`: The address of the message to retrieve.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Message>> {
        let msg_ids = self.client().get_message().index(address.to_msg_index()).await?;
        ensure!(!msg_ids.is_empty(), "no message found at index '{}'", address);

        let msgs = try_join_all(msg_ids.iter().map(|msg| {
            self.client()
                .get_message()
                .data(msg)
                .map_err(Into::into)
                .and_then(|iota_message| ready(iota_message.try_into()))
        }))
        .await?;
        Ok(msgs)
    }
}

impl TryFrom<IotaMessage> for TransportMessage {
    type Error = anyhow::Error;
    fn try_from(message: IotaMessage) -> Result<Self> {
        if let Some(Payload::Indexation(indexation)) = message.payload() {
            Ok(Self::new(indexation.data().into()))
        } else {
            Err(anyhow!(
                "expected an indexation payload from the Tangle, received something else"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::{
        address::{Address, AppAddr, MsgId},
        id::Identifier,
        message::{Topic, TransportMessage},
    };

    use super::*;

    #[tokio::test]
    async fn send_message() -> Result<()> {
        let mut client = Client::for_node("https://chrysalis-nodes.iota.org").await?;
        let msg = TransportMessage::new(vec![12; 1024]);
        let response: TransportMessage = client
            .send_message(
                Address::new(
                    AppAddr::default(),
                    MsgId::gen(
                        AppAddr::default(),
                        &Identifier::default(),
                        &Topic::default(),
                        Utc::now().timestamp_millis() as usize,
                    ),
                ),
                msg.clone(),
            )
            .await?;
        assert_eq!(msg, response);
        Ok(())
    }
}
