use anyhow::Result;

#[cfg(not(feature = "async"))]
use core::cell::RefCell;
use core::hash;
#[cfg(feature = "async")]
use core::marker::{
    Send,
    Sync,
};

#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
use iota_streams_core::prelude::Box;
#[cfg(not(feature = "async"))]
use iota_streams_core::prelude::Rc;
use iota_streams_core::prelude::{Vec, string::ToString};

pub trait TransportOptions {
    type SendOptions;
    fn get_send_options(&self) -> Self::SendOptions;
    fn set_send_options(&mut self, opt: Self::SendOptions);

    type RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions;
    fn set_recv_options(&mut self, opt: Self::RecvOptions);
}

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
#[cfg(not(feature = "async"))]
pub trait Transport<Link: Debug + Display, Msg>: TransportOptions {
    /// Send a message with default options.
    fn send_message(&mut self, msg: &Msg) -> Result<()>;

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        let mut msgs = self.recv_messages(link)?;
        if let Some(msg) = msgs.pop() {
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string()))?;
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait Transport<Link, Msg>: TransportOptions
where
    Link: Send + Sync,
    Msg: Send + Sync,
{
    /// Send a message with default options.
    async fn send_message(&mut self, msg: &Msg) -> Result<()>;

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg>;
    // For some reason compiler requires (Msg: `async_trait) lifetime bound for this default implementation.
    // {
    // let mut msgs = self.recv_messages(link).await?;
    // if let Some(msg) = msgs.pop() {
    // ensure!(msgs.is_empty(), "More than one message found.");
    // Ok(msg)
    // } else {
    // err!()
    // }
    // }
}

#[cfg(not(feature = "async"))]
impl<Tsp: TransportOptions> TransportOptions for Rc<RefCell<Tsp>> {
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    fn get_send_options(&self) -> Self::SendOptions {
        (&*self).borrow().get_send_options()
    }
    fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).borrow_mut().set_send_options(opt)
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).borrow().get_recv_options()
    }
    fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).borrow_mut().set_recv_options(opt)
    }
}

#[cfg(not(feature = "async"))]
impl<Link: Debug + Display, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Rc<RefCell<Tsp>> {
    /// Send a message.
    fn send_message(&mut self, msg: &Msg) -> Result<()> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.send_message(msg),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_messages(link),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_message(link),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }
}

mod bucket;
pub use bucket::BucketTransport;
use core::fmt::{Debug, Display};
use iota_streams_core::{try_or, err, wrapped_err, WrappedError, LOCATION_LOG};
use iota_streams_core::Errors::{MessageNotUnique, MessageLinkNotFound, TransportNotAvailable};

#[cfg(feature = "tangle")]
pub mod tangle;
