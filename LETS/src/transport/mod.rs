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
pub trait Transport<'a> {
    type Address;
    type Msg;
    type SendResponse;
    // TODO: CONSIDER CONVERTING TYPE PARAMETERS TO ASSOCIATED TYPES
    /// Send a message
    async fn send_message(&mut self, link: Self::Address, msg: Self::Msg) -> Result<Self::SendResponse>
    where
        'a: 'async_trait;

    /// Receive messages
    async fn recv_messages(&mut self, link: Self::Address) -> Result<Vec<Self::Msg>>
    where
        'a: 'async_trait;

    /// Receive a single message
    async fn recv_message(&mut self, link: Self::Address) -> Result<Self::Msg>
    where
        Self::Address: Display + Clone + 'async_trait,
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
impl<'a, Tsp: Transport<'a>> Transport<'a> for Rc<RefCell<Tsp>> {
    type Address = Tsp::Address;
    type Msg = Tsp::Msg;
    type SendResponse = Tsp::SendResponse;

    // Send a message.
    async fn send_message(&mut self, link: Tsp::Address, msg: Tsp::Msg) -> Result<Tsp::SendResponse>
    where
        Self::Address: 'async_trait,
        Self::Msg: 'async_trait,
    {
        self.borrow_mut().send_message(link, msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: Tsp::Address) -> Result<Vec<Tsp::Msg>>
    where
        Self::Address: 'async_trait,
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
