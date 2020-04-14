use failure::{
    bail,
    ensure,
    Fallible,
};
use std::{
    collections::HashMap,
    hash,
};

use crate::message::TbinaryMessage;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
pub trait Transport<TW, F, Link> /* where Link: HasLink */ {
    type SendOptions;

    /// Send a message with explicit options.
    fn send_message_with_options(&mut self, msg: &TbinaryMessage<TW, F, Link>, opt: Self::SendOptions) -> Fallible<()>;

    /// Send a message with default options.
    fn send_message(&mut self, msg: &TbinaryMessage<TW, F, Link>) -> Fallible<()>
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
    ) -> Fallible<Vec<TbinaryMessage<TW, F, Link>>>;

    /// Receive messages with explicit options.
    fn recv_message_with_options(
        &mut self,
        link: &Link,
        opt: Self::RecvOptions,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let mut msgs = self.recv_messages_with_options(link, opt)?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            bail!("Message not found.");
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Fallible<Vec<TbinaryMessage<TW, F, Link>>>
    where
        Self::RecvOptions: Default,
    {
        self.recv_messages_with_options(link, Self::RecvOptions::default())
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Fallible<TbinaryMessage<TW, F, Link>>
    where
        Self::RecvOptions: Default,
    {
        self.recv_message_with_options(link, Self::RecvOptions::default())
    }
}

pub struct BucketTransport<TW, F, Link> {
    bucket: HashMap<Link, Vec<TbinaryMessage<TW, F, Link>>>,
}

impl<TW, F, Link> BucketTransport<TW, F, Link>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

impl<TW, F, Link> Transport<TW, F, Link> for BucketTransport<TW, F, Link>
where
    TW: Clone,
    Link: Eq + hash::Hash + Clone,
{
    type SendOptions = ();

    fn send_message_with_options(&mut self, msg: &TbinaryMessage<TW, F, Link>, _opt: ()) -> Fallible<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    fn recv_messages_with_options(&mut self, link: &Link, _opt: ()) -> Fallible<Vec<TbinaryMessage<TW, F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}

pub mod tangle;
