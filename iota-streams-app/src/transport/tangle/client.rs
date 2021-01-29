#[cfg(not(feature = "async"))]
use smol::block_on;

#[cfg(feature = "async")]
use iota_streams_core::prelude::Rc;
#[cfg(feature = "async")]
use core::cell::RefCell;

use iota::{
    client as iota_client,
    Message,
    message::payload::Payload
};

use iota_streams_core::{
    prelude::Vec,
    {Errors::*, wrapped_err, try_or, err, WrappedError, LOCATION_LOG, Result},
};

use crate::{
    message::BinaryMessage,
    transport::{
        tangle::*,
        *,
    },
};

use futures::future::join_all;

use crate::std::borrow::ToOwned;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

#[derive(Clone, Copy)]
pub struct SendOptions {
    pub depth: u8,
    pub min_weight_magnitude: u8,
    pub local_pow: bool,
    pub threads: usize,
}

impl Default for SendOptions {
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
    result.map_err(|err| wrapped_err!(ClientOperationFailure, WrappedError(err)))
}

/// Reconstruct Streams Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `(client.get_message().index`.
pub fn msg_from_tangle_message<F>(message: &Message, link: &TangleAddress) -> Result<TangleMessage<F>> {
    if let Payload::Indexation(i) = message.payload().as_ref().unwrap() {
        let binary = BinaryMessage::new(link.clone(), i.data().to_owned().into());
        // TODO get timestamp
        let timestamp: u64 = 0;
    
        Ok(TangleMessage { binary, timestamp })
    } else {
        err!(BadMessagePayload)
    }
}

async fn get_messages(client: &iota_client::Client, tx_address: &[u8], tx_tag: &[u8]) -> Result<Vec<Message>> {
    let total = [tx_address, tx_tag].concat();
    let mut s = DefaultHasher::new();
    s.write(&total);
    let hash = s.finish();

    let msg_ids = handle_client_result(client.get_message()
            .index(&hash.to_string())
            .await
        ).unwrap();
    try_or!(!msg_ids.is_empty(), IndexNotFound)?;

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
    try_or!(!msgs.is_empty(), MessageContentsNotFound)?;
    Ok(msgs)
}

pub async fn async_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>) -> Result<()> {
    let total = [msg.binary.link.appinst.as_ref(), msg.binary.link.msgid.as_ref()].concat();
    let mut s = DefaultHasher::new();
    s.write(&total);
    let hash = s.finish();
    let binary = &msg.binary;

    //TODO: Get rid of copy caused by to_owned
    client
        .send()
        .with_index(&hash.to_string())
        .with_data(binary.body.bytes.to_owned())
        .finish()
        .await?;
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
pub fn sync_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>) -> Result<()> {
    block_on(async_send_message_with_options(client, msg))
}

#[cfg(not(feature = "async"))]
pub fn sync_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    block_on(async_recv_messages(client, link))
}

/// Stub type for iota_client::Client.  Removed: Copy, Default, Clone
pub struct Client {
    send_opt: SendOptions,
    client: iota_client::Client,
}

impl Default for Client {
    // Creates a new instance which links to a node on localhost:14265
    fn default() -> Self {
        Self {
            send_opt: SendOptions::default(),
            client: iota_client::ClientBuilder::new().with_node("http://localhost:14265").unwrap().finish().unwrap()
        }
    }
}

impl Client {
    // Create an instance of Client with a ready client and its send options
    pub fn new(options: SendOptions, client: iota_client::Client) -> Self {
        Self {
            send_opt: options,
            client: client
        }
    }

    // Create an instance of Client with a node pointing to the given URL
    pub fn new_from_url(url: &str) -> Self {
        Self {
            send_opt: SendOptions::default(),
            client: iota_client::ClientBuilder::new().with_node(url).unwrap().finish().unwrap()
        }
    }
}

impl TransportOptions for Client {
    type SendOptions = SendOptions;
    fn get_send_options(&self) -> SendOptions {
        self.send_opt.clone()
    }
    fn set_send_options(&mut self, opt: SendOptions) {
        self.send_opt = opt;
        
        //TODO
        //self.client.set_send_options()
    }

    type RecvOptions = ();
    fn get_recv_options(&self) -> () {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client {
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
    fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        sync_send_message_with_options(&self.client, msg)
    }

    /// Receive a message.
    fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        sync_recv_messages(&self.client, link)
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
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
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string()))?;
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}

// It's safe to impl async trait for Rc<RefCell<T>> targeting wasm as it's single-threaded.
#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Rc<RefCell<Client>>
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
    async fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => async_send_message_with_options(&tsp.client, msg, &tsp.send_opt).await,
            Err(_err) => err!(TransportNotAvailable),
        }
    }

    /// Receive a message.
    async fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => async_recv_messages(&tsp.client, link).await,
            Err(err) => err!(TransportNotAvailable),
        }
    }

    async fn recv_message(&mut self, link: &TangleAddress) -> Result<TangleMessage<F>> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => {
                let mut msgs = async_recv_messages(&tsp.client, link).await?;
                if let Some(msg) = msgs.pop() {
                    try_or!(msgs.is_empty(), MessageNotUnique(link.msgid.to_string()));
                    Ok(msg)
                } else {
                    err!(MessageLinkNotFound(link.msgid.to_string()))
                }
            },
            Err(err) => err!(TransportNotAvailable),
        }
    }
}
