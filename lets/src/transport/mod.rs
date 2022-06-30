// Rust
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;

// 3rd-party
use anyhow::{anyhow, ensure, Result};
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

// Arc<Mutex<Transport>> blanket impl is provided only behind the "sync-spin" or "sync-parking-lot"
// features,  as a convenience for users that want to share a transport through several user
// instances. We provide 2 flavours of Mutex: `parking_lot` and `spin`:
// - `sync-parking-lot` feature enables `parking_lot::Mutex` Mutex (requires `std`)
// - `sync-spin` feature enables `spin::Mutex` (supports no-std)
// If both features are provided, `parking_lot` is used.
#[cfg(any(feature = "sync-spin", feature = "sync-parking-lot"))]
mod sync {
    use alloc::{boxed::Box, sync::Arc, vec::Vec};

    use anyhow::Result;
    use async_trait::async_trait;
    #[cfg(feature = "sync-parking-lot")]
    use parking_lot::Mutex;
    #[cfg(all(feature = "sync-spin", not(feature = "sync-parking-lot")))]
    use spin::Mutex;

    use crate::address::Address;

    use super::Transport;

    #[async_trait(?Send)]
    impl<'a, Tsp: Transport<'a>> Transport<'a> for Arc<Mutex<Tsp>> {
        type Msg = Tsp::Msg;
        type SendResponse = Tsp::SendResponse;

        // Send a message.
        async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse>
        where
            Self::Msg: 'async_trait,
        {
            self.lock().send_message(address, msg).await
        }

        // Receive messages with default options.
        async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>> {
            self.lock().recv_messages(address).await
        }
    }
}

pub mod bucket;

#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
pub mod tangle;

#[cfg(feature = "utangle-client")]
pub mod utangle;
