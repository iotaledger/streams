// Rust
use alloc::{
    boxed::Box,
    rc::Rc,
    vec::Vec,
};
use core::cell::RefCell;

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
use crate::address::Address;

/// Network transport abstraction.
/// Parametrized by the type of message addresss.
/// Message address is used to identify/locate a message (eg. like URL for HTTP).
#[async_trait(?Send)]
pub trait Transport<'a> {
    type Msg;
    type SendResponse;
    /// Send a message
    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse>
    where
        'a: 'async_trait;

    /// Receive messages
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
    where
        'a: 'async_trait;

    /// Receive a single message
    async fn recv_message(&mut self, address: Address) -> Result<Self::Msg> {
        let mut msgs = self.recv_messages(address).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found with address {}", address);
            Ok(msg)
        } else {
            Err(anyhow!("Message at address {} not found in transport", address))
        }
    }
}

#[async_trait(?Send)]
impl<'a, Tsp: Transport<'a>> Transport<'a> for Rc<RefCell<Tsp>> {
    type Msg = Tsp::Msg;
    type SendResponse = Tsp::SendResponse;

    // Send a message.
    async fn send_message(&mut self, address: Address, msg: Tsp::Msg) -> Result<Tsp::SendResponse>
    where
        Self::Msg: 'async_trait,
    {
        self.borrow_mut().send_message(address, msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Tsp::Msg>> {
        self.borrow_mut().recv_messages(address).await
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
    impl<address, Msg, Tsp: Transport<address, Msg>> Transport<address, Msg> for Arc<Mutex<Tsp>> {
        // Send a message.
        async fn send_message(&mut self, address: address, msg: Msg) -> Result<()>
        where
            Msg: 'async_trait,
        {
            self.lock().send_message(address, msg).await
        }

        // Receive messages with default options.
        async fn recv_messages(&mut self, address: address) -> Result<Vec<Msg>>
        where
            address: 'async_trait,
        {
            self.lock().recv_messages(address).await
        }
    }
}

pub mod bucket;

#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
pub mod tangle;
