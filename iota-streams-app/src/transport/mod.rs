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
pub trait Transport<Link, Msg>
{
    type SendOptions;
    fn get_send_options(&self) -> Self::SendOptions;
    fn set_send_options(&mut self, opt: Self::SendOptions);

    /// Send a message with default options.
    fn send_message(&mut self, msg: &Msg) -> Result<()>;

    type RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions;
    fn set_recv_options(&mut self, opt: Self::RecvOptions);

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg>
    {
        let mut msgs = self.recv_messages(link)?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait Transport<Link, Msg> where
    Link: Send + Sync,
    Msg: Send + Sync,
{
    type SendOptions;
    fn get_send_options(&self) -> Self::SendOptions;
    fn set_send_options(&mut self, opt: Self::SendOptions);

    /// Send a message with default options.
    async fn send_message(&mut self, msg: &Msg) -> Result<()>;

    type RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions;
    fn set_recv_options(&mut self, opt: Self::RecvOptions);

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg>;
    /*
    // For some reason compiler requires (Msg: `async_trait) lifetime bound for this default implementation.
    {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }
     */
}


#[cfg(not(feature = "async"))]
impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Rc<RefCell<Tsp>> {
    type SendOptions = <Tsp as Transport<Link, Msg>>::SendOptions;
    fn get_send_options(&self) -> Self::SendOptions {
        (&*self).borrow().get_send_options()
    }
    fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).borrow_mut().set_send_options(opt)
    }

    /// Send a message.
    fn send_message(&mut self, msg: &Msg) -> Result<()>
    {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.send_message(msg),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    type RecvOptions = <Tsp as Transport<Link, Msg>>::RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).borrow().get_recv_options()
    }
    fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).borrow_mut().set_recv_options(opt)
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>
    {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_messages(link),
            Err(err) => Err(anyhow!("Transport already borrowed: {}", err)),
        }
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg>
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
