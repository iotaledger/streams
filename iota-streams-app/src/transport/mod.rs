use anyhow::{
    anyhow,
    ensure,
    Result,
};

use core::hash;
#[cfg(not(feature = "async"))]
use core::cell::RefCell;
#[cfg(feature = "async")]
use core::marker::{
    Send,
    Sync,
};

#[cfg(feature = "async")]
use async_trait::async_trait;

use iota_streams_core::prelude::Vec;
#[cfg(not(feature = "async"))]
use iota_streams_core::prelude::Rc;
#[cfg(feature = "async")]
use iota_streams_core::prelude::Box;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
#[cfg(not(feature = "async"))]
pub trait Transport<Link, Msg> // where Link: HasLink
{
    type SendOptions;

    /// Send a message with explicit options.
    fn send_message_with_options(&mut self, msg: &Msg, opt: &Self::SendOptions) -> Result<()>;

    /// Send a message with default options.
    fn send_message(&mut self, msg: &Msg) -> Result<()>
    where
        Self::SendOptions: Default,
    {
        self.send_message_with_options(msg, &Self::SendOptions::default())
    }

    type RecvOptions;

    /// Receive messages with explicit options.
    fn recv_messages_with_options(
        &mut self,
        link: &Link,
        opt: &Self::RecvOptions,
    ) -> Result<Vec<Msg>>;

    /// Receive messages with explicit options.
    fn recv_message_with_options(&mut self, link: &Link, opt: &Self::RecvOptions) -> Result<Msg> {
        let mut msgs = self.recv_messages_with_options(link, opt)?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>
    where
        Self::RecvOptions: Default,
    {
        self.recv_messages_with_options(link, &Self::RecvOptions::default())
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg>
    where
        Self::RecvOptions: Default,
    {
        self.recv_message_with_options(link, &Self::RecvOptions::default())
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait Transport<Link, Msg> where
    Link: Send + Sync,
    Msg: Send + Sync,
{
    type SendOptions: Send;

    /// Send a message with explicit options.
    async fn send_message_with_options(&mut self, msg: &Msg, opt: &Self::SendOptions) -> Result<()>;

    /// Send a message with default options.
    async fn send_message(&mut self, msg: &Msg) -> Result<()>
    where
        Self::SendOptions: Default + Send + Sync,
    {
        self.send_message_with_options(msg, &Self::SendOptions::default()).await
    }

    type RecvOptions: Send + Sync;

    /// Receive messages with explicit options.
    async fn recv_messages_with_options(
        &mut self,
        link: &Link,
        opt: &Self::RecvOptions,
    ) -> Result<Vec<Msg>>;

    /// Receive messages with explicit options.
    async fn recv_message_with_options(&mut self, link: &Link, opt: &Self::RecvOptions) -> Result<Msg> {
        let mut msgs = self.recv_messages_with_options(link, opt).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>
    where
        Self::RecvOptions: Default + Send,
    {
        self.recv_messages_with_options(link, &Self::RecvOptions::default()).await
    }

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg>
    where
        Self::RecvOptions: Default + Send,
    {
        self.recv_message_with_options(link, &Self::RecvOptions::default()).await
    }
}


#[cfg(not(feature = "async"))]
impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Rc<RefCell<Tsp>> {
    type SendOptions = <Tsp as Transport<Link, Msg>>::SendOptions;

    fn send_message_with_options(&mut self, msg: &Msg, opt: &Self::SendOptions) -> Result<()> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.send_message_with_options(msg, opt),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    /// Send a message with default options.
    fn send_message(&mut self, msg: &Msg) -> Result<()>
    where
        Self::SendOptions: Default,
    {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.send_message(msg),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    type RecvOptions = <Tsp as Transport<Link, Msg>>::RecvOptions;

    /// Receive messages with explicit options.
    fn recv_messages_with_options(
        &mut self,
        link: &Link,
        opt: &Self::RecvOptions,
    ) -> Result<Vec<Msg>> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_messages_with_options(link, opt),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    /// Receive messages with explicit options.
    fn recv_message_with_options(&mut self, link: &Link, opt: &Self::RecvOptions) -> Result<Msg> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_message_with_options(link, opt),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>
    where
        Self::RecvOptions: Default,
    {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_messages(link),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg>
    where
        Self::RecvOptions: Default,
    {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_message(link),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }
}

mod bucket;
pub use bucket::BucketTransport;

#[cfg(feature = "tangle")]
pub mod tangle;
