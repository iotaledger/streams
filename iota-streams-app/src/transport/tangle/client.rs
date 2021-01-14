use anyhow::{
    anyhow,
    ensure,
    Result,
};

#[cfg(not(feature = "async"))]
use smol::block_on;

use iota::{
    client as iota_client,
    Message, MessageId, MessageBuilder, ClientMiner,
    message::payload::{
        indexation::Indexation,
        Payload
    }
};

use iota_streams_core::prelude::Vec;

use crate::{
    message::BinaryMessage,
    transport::{
        tangle::*,
        *,
    },
};

use futures::future::join_all;
use std::boxed::Box;
use std::str;

#[derive(Clone, Copy)]
pub struct SendTrytesOptions {
    pub depth: u8,
    pub min_weight_magnitude: u8,
    pub local_pow: bool,
    pub threads: usize,
}

impl Default for SendTrytesOptions {
    fn default() -> Self {
        Self {
            depth: 3,
            min_weight_magnitude: 14,
            local_pow: true,
            threads: num_cpus::get(),
        }
    }
}

fn handle_client_result<T>(result: iota_client::Result<T>) -> Result<T> {
    result.map_err(|err| anyhow!("Failed iota_client: {}", err))
}

/// Reconstruct Streams Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `bundles_from_trytes`.
pub fn msg_from_tangle_message<F>(message: &Message, link: &TangleAddress) -> Result<TangleMessage<F>> {
    if let Payload::Indexation(i) = message.payload().as_ref().unwrap() {
        let binary = BinaryMessage::new(link.clone(), hex::decode(i.data())?.into());
    
        // TODO get timestamp
        let timestamp: u64 = 0;
    
        Ok(TangleMessage { binary, timestamp })
    } else {
        Err(anyhow!("Message is not a Indexation type"))
    }
}

async fn get_messages(client: &iota_client::Client, tx_address: &[u8], tx_tag: &[u8]) -> Result<Vec<Message>> {
    let msg_ids = handle_client_result(client.get_message()
            .index(&hex::encode([tx_address, tx_tag].concat()))
            .await
        ).unwrap();
    ensure!(!msg_ids.is_empty(), "Messade ids not found.");

    let msgs = join_all(
        msg_ids.iter().map(|msg| {
            async move {
                handle_client_result(client
                    .get_message()
                    .data(msg)
                    .await
                ).unwrap()
            }
        }
    )).await;
    ensure!(!msgs.is_empty(), "Messages not found.");
    Ok(msgs)
}

fn make_bundle(
    address: &[u8],
    tag: &[u8],
    body: &[u8],
    _timestamp: u64,
    trunk: MessageId,
    branch: MessageId,
) -> Result<Vec<Message>> {
    let mut msgs = Vec::new();

    dbg!( hex::encode([address, tag].concat()));
    let payload = Indexation::new(
        hex::encode([address, tag].concat()), 
        body).unwrap();
    //TODO: Multiple messages if payload size is over max. Currently no max decided
    let msg = MessageBuilder::<ClientMiner>::new()
        .with_parent1(trunk)
        .with_parent2(branch)
        .with_payload(Payload::Indexation(Box::new(payload)))
        .finish();

    msgs.push(msg.unwrap());
    Ok(msgs)
}

pub fn msg_to_tangle<F>(
    msg: &BinaryMessage<F, TangleAddress>,
    timestamp: u64,
    trunk: MessageId,
    branch: MessageId,
) -> Result<Vec<Message>> {
    make_bundle(
        msg.link.appinst.as_ref(),
        msg.link.msgid.as_ref(),
        &msg.body.bytes,
        timestamp,
        trunk,
        branch,
    )
}

async fn send_messages(client: &iota_client::Client, _opt: &SendTrytesOptions, msgs: Vec<Message>) -> Result<Vec<MessageId>> {
    let msgs = join_all(
        msgs.iter().map(|msg| {
            async move {
                handle_client_result(client.post_message(msg).await).unwrap()
            }
        }
    )).await;

    Ok(msgs)
}

pub async fn async_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>, opt: &SendTrytesOptions) -> Result<()> {
    // TODO: Get trunk and branch hashes. Although, `send_trytes` should get these hashes.
    let tips = client.get_tips().await.unwrap();
    let messages = msg_to_tangle(&msg.binary, msg.timestamp, tips.0, tips.1)?;

    // Ignore attached transactions.
    send_messages(client, opt, messages).await?;
    Ok(())
}

pub async fn async_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    let tx_address = link.appinst.as_ref();
    let tx_tag = link.msgid.as_ref();
    match get_messages(client, tx_address, tx_tag).await {
        Ok(txs) => Ok(txs.iter()
            .map(|b| msg_from_tangle_message(b, link).unwrap())
            .collect()),
        Err(_) => Ok(Vec::new()), // Just ignore the error?
    }
}

#[cfg(not(feature = "async"))]
pub fn sync_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>, opt: &SendTrytesOptions) -> Result<()> {
    block_on(async_send_message_with_options(client, msg, opt))
}

#[cfg(not(feature = "async"))]
pub fn sync_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    block_on(async_recv_messages(client, link))
}

/// Stub type for iota_client::Client.  Removed: Copy, Default, Clone
pub struct Client {
    send_opt: SendTrytesOptions,
    client: iota_client::Client,
}

impl Default for Client {
    // Creates a new instance which links to a node on localhost:14265
    fn default() -> Self {
        Self {
            send_opt: SendTrytesOptions::default(),
            client: iota_client::ClientBuilder::new().with_node("http://localhost:14265").unwrap().finish().unwrap()
        }
    }
}

impl Client {
    // Create an instance of Client with a ready client and its send options
    pub fn new(options: SendTrytesOptions, client: iota_client::Client) -> Self {
        Self {
            send_opt: options,
            client: client
        }
    }
    
    // Create an instance of Client with a node pointing to the given URL
    pub fn new_from_url(url: &str) -> Self {
        Self {
            send_opt: SendTrytesOptions::default(),
            client: iota_client::ClientBuilder::new().with_node(url).unwrap().finish().unwrap()
        }
    }
}

impl TransportOptions for Client {
    type SendOptions = SendTrytesOptions;
    fn get_send_options(&self) -> SendTrytesOptions {
        self.send_opt.clone()
    }
    fn set_send_options(&mut self, opt: SendTrytesOptions) {
        self.send_opt = opt;
    }

    type RecvOptions = ();
    fn get_recv_options(&self) -> () {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client {
    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        sync_send_message_with_options(&self.client, msg, &self.send_opt)
    }

    /// Receive a message.
    fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        sync_recv_messages(&self.client, link)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    async fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        async_send_message_with_options(&self.client, msg, &self.send_opt).await
    }

    /// Receive a message.
    async fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        async_recv_messages(&self.client, link).await
    }

    async fn recv_message(&mut self, link: &TangleAddress) -> Result<TangleMessage<F>> {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }
}
