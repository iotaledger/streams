// Rust
use alloc::{
    boxed::Box,
    rc::Rc,
    vec::Vec,
};
use core::{
    cell::RefCell,
    fmt::Display,
};

// 3rd-party
use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;

// IOTA

// Streams

// Local

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
#[async_trait(?Send)]
pub trait Transport<Address, Msg, SendResponse> {
    // TODO: CONSIDER CONVERTING TYPE PARAMETERS TO ASSOCIATED TYPES
    /// Send a message
    async fn send_message(&mut self, link: Address, msg: Msg) -> Result<SendResponse>
    where
        Msg: 'async_trait,
        Address: 'async_trait;
    // 'async_trait is necessary when the type implementing transport has type parameters
    // (see https://github.com/dtolnay/async-trait/issues/8#issuecomment-514812245)

    /// Receive messages
    async fn recv_messages(&mut self, link: Address) -> Result<Vec<Msg>>
    where
        Address: 'async_trait;

    /// Receive a single message
    async fn recv_message(&mut self, link: Address) -> Result<Msg>
    where
        Address: Display + Clone + 'async_trait,
    {
        let mut msgs = self.recv_messages(link.clone()).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found with address {}", link);
            Ok(msg)
        } else {
            Err(anyhow!("Message at link {} not found in transport", link))
        }
    }
}

#[async_trait(?Send)]
impl<Link, Msg, SendResponse, Tsp: Transport<Link, Msg, SendResponse>> Transport<Link, Msg, SendResponse>
    for Rc<RefCell<Tsp>>
{
    // Send a message.
    async fn send_message(&mut self, link: Link, msg: Msg) -> Result<SendResponse>
    where
        Msg: 'async_trait,
        Link: 'async_trait,
    {
        self.borrow_mut().send_message(link, msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: Link) -> Result<Vec<Msg>>
    where
        Link: 'async_trait,
    {
        self.borrow_mut().recv_messages(link).await
    }
}

#[cfg(any(feature = "sync-spin", feature = "sync-parking-lot"))]
mod sync {
    use super::{
        Transport,
        TransportDetails,
        TransportOptions,
    };
    use iota_streams_core::{
        async_trait,
        prelude::{
            Arc,
            Box,
            Mutex,
            Vec,
        },
        Result,
    };

    #[async_trait(?Send)]
    impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Arc<Mutex<Tsp>> {
        // Send a message.
        async fn send_message(&mut self, link: Link, msg: Msg) -> Result<()>
        where
            Msg: 'async_trait,
        {
            self.lock().send_message(link, msg).await
        }

        // Receive messages with default options.
        async fn recv_messages(&mut self, link: Link) -> Result<Vec<Msg>>
        where
            Link: 'async_trait,
        {
            self.lock().recv_messages(link).await
        }
    }
}

pub mod bucket;

#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
pub mod tangle;
