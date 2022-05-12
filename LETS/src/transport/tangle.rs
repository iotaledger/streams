// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};
use core::{
    convert::{
        TryFrom,
        TryInto,
    },
    marker::PhantomData,
};

// 3rd-party
use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;
use futures::{
    future::{
        ready,
        try_join_all,
    },
    TryFutureExt,
};

// IOTA
use iota_client::bee_message::{
    payload::Payload,
    Message as IotaMessage,
};

// Streams

// Local
use crate::{
    link::Address,
    message::TransportMessage,
    transport::Transport,
};

#[derive(Debug)]
pub struct Client<Message = TransportMessage, SendResponse = TransportMessage>(
    iota_client::Client,
    PhantomData<(Message, SendResponse)>,
);

impl<Message, SendResponse> Client<Message, SendResponse> {
    // Create an instance of Client with a ready client and its send options
    pub fn new(client: iota_client::Client) -> Self {
        Self(client, PhantomData)
    }

    // Shortcut to create an instance of Client connecting to a node with default parameters
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

    pub fn client(&self) -> &iota_client::Client {
        &self.0
    }

    pub fn client_mut(&mut self) -> &mut iota_client::Client {
        &mut self.0
    }
}

#[async_trait(?Send)]
impl<'a, Message, SendResponse> Transport<'a> for Client<Message, SendResponse>
where
    Message: Into<Vec<u8>> + TryFrom<IotaMessage, Error = anyhow::Error>,
    SendResponse: TryFrom<IotaMessage, Error = anyhow::Error>,
{
    type Address = &'a Address;
    type Msg = Message;
    type SendResponse = SendResponse;

    async fn send_message(&mut self, address: &'a Address, msg: Message) -> Result<SendResponse>
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

    async fn recv_messages(&mut self, address: &'a Address) -> Result<Vec<Message>> {
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
