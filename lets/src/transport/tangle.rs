// Rust
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
    str::FromStr,
};

// 3rd-party
use async_trait::async_trait;
use futures::{
    future::{ready, try_join_all},
    TryFutureExt,
};

// IOTA
use iota_client::{
    block::{payload::Payload, Block, BlockId},
    node_api::indexer::query_parameters::QueryParameter,
};

// Streams

// Local
use crate::{
    address::Address,
    error::{Error, Result},
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
                .with_node(node_url)
                .map_err(|e| Error::IotaClient("building client", e))?
                .with_local_pow(true)
                .finish()
                .map_err(|e| Error::External(e.into()))?,
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
impl<Message, SendResponse> Transport<'_> for Client<Message, SendResponse>
where
    Message: Into<Vec<u8>> + TryFrom<Block, Error = crate::error::Error>,
    SendResponse: TryFrom<Block, Error = crate::error::Error>,
{
    type Msg = Message;
    type SendResponse = SendResponse;

    async fn send_message(&mut self, address: Address, msg: Message) -> Result<SendResponse>
    where
        Message: 'async_trait,
    {
        let tag = prefix_hex::encode(address.to_msg_index());
        let block = self
            .client()
            .block()
            .with_tag(tag.as_bytes().to_vec())
            .with_data(msg.into())
            .finish()
            .await
            .map_err(|e| Error::IotaClient("sending message", e))?;
        let id = block.id();
        let _id_str = id.to_string();
        block.try_into()
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Message>> {
        let tag = prefix_hex::encode(address.to_msg_index());
        let output_ids = self
            .client()
            .basic_output_ids(vec![QueryParameter::Tag(tag)])
            .await
            .map_err(|e| Error::IotaClient("get messages by index", e))?;

        if output_ids.is_empty() {
            return Err(Error::MessageMissing(address, "transport"));
        }

        let outputs = try_join_all(output_ids.iter().map(|output| {
            self.client()
                .get_output(output)
                .map_err(|e| Error::IotaClient("receiving message", e))
                .and_then(|output| {
                    ready(
                        BlockId::from_str(&output.metadata.block_id)
                            .map_err(|e| Error::IotaClient("creating BlockId", e.into())),
                    )
                })
        }))
        .await?;

        let msgs = try_join_all(outputs.iter().map(|blockid| {
            self.client()
                .get_block(blockid)
                .map_err(|e| Error::IotaClient("get iota block by id", e))
                .and_then(|msg| ready(msg.try_into()))
        }))
        .await?;
        Ok(msgs)
    }
}

impl TryFrom<Block> for TransportMessage {
    type Error = crate::error::Error;
    fn try_from(message: Block) -> Result<Self> {
        if let Some(Payload::TaggedData(indexation)) = message.payload() {
            Ok(Self::new(indexation.data().into()))
        } else {
            Err(Error::Malformed(
                "payload from the Tangle",
                "TaggedDataPayload",
                alloc::string::ToString::to_string(&message.id()),
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
