// Rust
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

// 3rd-party
use async_trait::async_trait;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize};

// IOTA
use bee_ternary::{b1t6, Btrit, T1B1Buf, TritBuf};
use crypto::hashes::{
    blake2b::Blake2b256,
    ternary::{self, curl_p},
    Digest,
};

// Streams

// Local
use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};

const NONCE_SIZE: usize = core::mem::size_of::<u64>();
// Precomputed natural logarithm of 3 for performance reasons.
// See https://oeis.org/A002391.
const LN_3: f64 = 1.098_612_288_668_109;

/// A [`Transport`] Client for sending and retrieving binary messages from an `IOTA Tangle` node.
/// This Client uses a lightweight [reqwest](`reqwest::Client`) Client implementation.
#[derive(Debug, Clone)]
pub struct Client<Message = TransportMessage, SendResponse = Ignored> {
    /// Node endpoint URL
    node_url: String,
    /// HTTP Client
    client: reqwest::Client,
    _phantom: PhantomData<(Message, SendResponse)>,
}

impl<M, S> Default for Client<M, S> {
    fn default() -> Self {
        Self {
            node_url: String::from("https://chrysalis-nodes.iota.org"),
            client: reqwest::Client::new(),
            _phantom: PhantomData,
        }
    }
}

impl<Message, SendResponse> Client<Message, SendResponse> {
    /// Creates a new `uTangle` [`Client`] implementation from the provided URL
    ///
    /// # Arguments:
    /// * `node_url`: Tangle node endpoint
    pub fn new<U>(node_url: U) -> Self
    where
        U: Into<String>,
    {
        Self {
            node_url: node_url.into(),
            client: reqwest::Client::new(),
            _phantom: PhantomData,
        }
    }

    /// Returns basic network details from node request
    async fn get_network_info(&self) -> Result<NetworkInfo> {
        let network_info_path = "api/v1/info";
        let network_info: Response<NetworkInfo> = self
            .client
            .get(format!("{}/{}", self.node_url, network_info_path))
            .send()
            .await?
            .json()
            .await?;
        Ok(network_info.data)
    }

    /// Returns [`Tips`] from node request
    async fn get_tips(&self) -> Result<Tips> {
        let tips_path = "api/v1/tips";
        let tips: Response<Tips> = self
            .client
            .get(format!("{}/{}", self.node_url, tips_path))
            .send()
            .await?
            .json()
            .await?;
        Ok(tips.data)
    }

    /// Serialise message contents into single byte array for sending
    ///
    /// # Arguments
    /// * `network_info`: [`NetworkInfo`] response from node
    /// * `tips`: [`Tips`] response from node
    /// * `address`: Address of the message being sent
    /// * `msg`: Payload bytes for the message
    fn pack_message(&self, network_info: NetworkInfo, tips: Tips, address: Address, msg: &[u8]) -> Result<Vec<u8>> {
        let mut message_bytes = Vec::new();
        // Network-ID
        message_bytes.extend(&Blake2b256::digest(network_info.network_id.as_bytes())[..8]);
        // Parent Messages
        message_bytes.extend((tips.ids.len() as u8).to_le_bytes());
        for tip in tips.ids {
            message_bytes.extend(hex::decode(tip)?);
        }

        let index = address.to_msg_index();
        // Size of whole payload (payload-type + index-size + index + data-size + data)
        message_bytes.extend(((4 + 2 + index.len() + 4 + msg.len()) as u32).to_le_bytes());
        // payload-type (Indexation = 2)
        message_bytes.extend(2_u32.to_le_bytes());
        // index-size
        message_bytes.extend((index.len() as u16).to_le_bytes());
        // index
        message_bytes.extend(index);
        // data-size
        message_bytes.extend((msg.len() as u32).to_le_bytes());
        // data
        message_bytes.extend(msg);
        // nonce
        message_bytes.extend(nonce(&message_bytes, network_info.min_pow_score)?.to_le_bytes());

        Ok(message_bytes)
    }
}

#[async_trait(?Send)]
impl<Message, SendResponse> Transport<'_> for Client<Message, SendResponse>
where
    Message: AsRef<[u8]> + TryFrom<TangleMessage, Error = crate::error::Error>,
    SendResponse: DeserializeOwned,
{
    type Msg = Message;
    type SendResponse = SendResponse;

    /// Sends a message indexed at the provided [`Address`] to the tangle.
    ///
    /// # Arguments
    /// * `address`: The address of the message.
    /// * `msg`: Message - The message to send.
    async fn send_message(&mut self, address: Address, msg: Message) -> Result<SendResponse>
    where
        Message: 'async_trait,
    {
        let network_info = self.get_network_info().await?;
        let tips = self.get_tips().await?;

        let message_bytes = self.pack_message(network_info, tips, address, msg.as_ref())?;

        let path = "api/v1/messages";
        let response: SendResponse = self
            .client
            .post(format!("{}/{}", self.node_url, path))
            .header("Content-Type", "application/octet-stream")
            .body(message_bytes)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Retrieves a message indexed at the provided [`Address`] from the tangle. Errors if no
    /// messages are found.
    ///
    /// # Arguments
    /// * `address`: The address of the message to retrieve.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Message>> {
        let path = "api/v1/messages";
        let index_data: Response<IndexResponse> = self
            .client
            .get(format!("{}/{}", self.node_url, path))
            .query(&[("index", hex::encode(address.to_msg_index()))])
            .send()
            .await?
            .json()
            .await?;

        let msg_id = index_data
            .data
            .message_ids
            .first()
            .ok_or(Error::AddressError("No message found", address))?;
        let msg: Response<TangleMessage> = self
            .client
            .get(format!("{}/{}/{}", self.node_url, path, msg_id))
            .send()
            .await?
            .json()
            .await?;
        Ok(vec![msg.data.try_into()?])
    }
}

fn nonce(data: &[u8], target_score: f64) -> Result<u64> {
    let target_zeros = (((data.len() + NONCE_SIZE) as f64 * target_score).ln() / LN_3).ceil() as usize;
    let hash = Blake2b256::digest(data);
    let mut pow_digest = TritBuf::<T1B1Buf>::new();
    b1t6::encode::<T1B1Buf>(&hash).iter().for_each(|t| pow_digest.push(t));
    (0..u32::MAX)
        .into_par_iter()
        .step_by(curl_p::BATCH_SIZE)
        .find_map_any(|n| {
            let mut hasher = curl_p::CurlPBatchHasher::<T1B1Buf>::new(ternary::HASH_LENGTH);
            for i in 0..curl_p::BATCH_SIZE {
                let mut buffer = TritBuf::<T1B1Buf>::zeros(ternary::HASH_LENGTH);
                buffer[..pow_digest.len()].copy_from(&pow_digest);
                let nonce_trits = b1t6::encode::<T1B1Buf>(&(n as u64 + i as u64).to_le_bytes());
                buffer[pow_digest.len()..pow_digest.len() + nonce_trits.len()].copy_from(&nonce_trits);
                hasher.add(buffer);
            }
            for (i, hash) in hasher.hash().enumerate() {
                let trailing_zeros = hash.iter().rev().take_while(|t| *t == Btrit::Zero).count();

                if trailing_zeros >= target_zeros {
                    return Some(n as u64 + i as u64);
                }
            }
            None
        })
        .ok_or(Error::Nonce(target_score))
}

#[derive(Deserialize)]
struct NetworkInfo {
    #[serde(rename = "networkId")]
    network_id: String,
    #[serde(rename = "minPoWScore")]
    min_pow_score: f64,
}

#[derive(Deserialize)]
struct Tips {
    #[serde(rename = "tipMessageIds")]
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct TangleMessage {
    payload: IndexationPayload,
}

#[derive(Deserialize)]
struct IndexationPayload {
    data: String,
}

#[derive(Deserialize)]
struct IndexResponse {
    #[serde(rename = "messageIds")]
    message_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct Ignored {}

#[derive(Deserialize)]
struct Response<T> {
    data: T,
}

impl TryFrom<TangleMessage> for TransportMessage {
    type Error = crate::error::Error;
    fn try_from(message: TangleMessage) -> Result<Self> {
        Ok(Self::new(hex::decode(message.payload.data)?))
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
    async fn send_and_recv_message() -> Result<()> {
        let mut client = Client::new("https://chrysalis-nodes.iota.org");
        let msg = TransportMessage::new(vec![12; 1024]);
        let address = Address::new(
            AppAddr::default(),
            MsgId::gen(
                AppAddr::default(),
                &Identifier::default(),
                &Topic::default(),
                Utc::now().timestamp_millis() as usize,
            ),
        );
        let _: serde_json::Value = client.send_message(address, msg.clone()).await?;

        let response = client.recv_message(address).await?;
        assert_eq!(msg, response);
        Ok(())
    }
}
