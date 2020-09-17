use anyhow::{
    bail,
    ensure,
    Result,
};
use core::hash;

use iota_streams_core::prelude::{
    HashMap,
    Vec,
};

use crate::message::BinaryMessage;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
pub trait Transport<F, Link> // where Link: HasLink
{
    type SendOptions;

    /// Send a message with explicit options.
    fn send_message_with_options(&mut self, msg: &BinaryMessage<F, Link>, opt: Self::SendOptions) -> Result<()>;

    /// Send a message with default options.
    fn send_message(&mut self, msg: &BinaryMessage<F, Link>) -> Result<()>
    where
        Self::SendOptions: Default,
    {
        self.send_message_with_options(msg, Self::SendOptions::default())
    }

    type RecvOptions;

    /// Receive messages with explicit options.
    fn recv_messages_with_options(
        &mut self,
        link: &Link,
        opt: Self::RecvOptions,
    ) -> Result<Vec<BinaryMessage<F, Link>>>;

    /// Receive messages with explicit options.
    fn recv_message_with_options(&mut self, link: &Link, opt: Self::RecvOptions) -> Result<BinaryMessage<F, Link>> {
        let mut msgs = self.recv_messages_with_options(link, opt)?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            bail!("Message not found.");
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<BinaryMessage<F, Link>>>
    where
        Self::RecvOptions: Default,
    {
        self.recv_messages_with_options(link, Self::RecvOptions::default())
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<BinaryMessage<F, Link>>
    where
        Self::RecvOptions: Default,
    {
        self.recv_message_with_options(link, Self::RecvOptions::default())
    }
}

pub struct BucketTransport<F, Link> {
    bucket: HashMap<Link, Vec<BinaryMessage<F, Link>>>,
}

impl<F, Link> BucketTransport<F, Link>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
#[async_trait]
impl<F, Link> Transport<F, Link> for BucketTransport<F, Link>
where
    Link: Eq + hash::Hash + Clone,
{
    type SendOptions = ();

    fn send_message_with_options(&mut self, msg: &BinaryMessage<F, Link>, _opt: ()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    fn recv_messages_with_options(&mut self, link: &Link, _opt: ()) -> Result<Vec<BinaryMessage<F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}

#[cfg(not(feature = "async"))]
impl<F, Link> Transport<F, Link> for BucketTransport<F, Link>
where
    Link: Eq + hash::Hash + Clone,
{
    type SendOptions = ();

    fn send_message_with_options(&mut self, msg: &BinaryMessage<F, Link>, _opt: ()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    fn recv_messages_with_options(&mut self, link: &Link, _opt: ()) -> Result<Vec<BinaryMessage<F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}

#[cfg(feature = "tangle")]
pub mod tangle;
