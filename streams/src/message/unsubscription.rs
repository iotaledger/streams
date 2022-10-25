//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```ddml
//! message Unsubscribe {
//!     join(spongos);
//!     absorb                  u8      identifier;
//!     commit;
//!     squeeze external        u8      hash[64];
//!     ed25519(hash)           u8      signature[64];
//! }
//! ```
// Rust
use alloc::boxed::Box;

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams
use lets::{
    id::{Identifier, Identity},
    message::{ContentSign, ContentSignSizeof, ContentSizeof, ContentUnwrap, ContentVerify, ContentWrap},
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Commit, Join, Mask},
        io,
    },
    error::Result,
    Spongos,
};

// Local

/// A struct that holds references needed for unsubscription message encoding
pub(crate) struct Wrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The [`Identity`] of the subscriber
    subscriber_id: &'a Identity,
}

impl<'a> Wrap<'a> {
    /// Creates a new [`Wrap`] struct for an unsubscription message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `subscriber_id`: The [`Identity`] of the subscriber.
    pub(crate) fn new(initial_state: &'a mut Spongos, subscriber_id: &'a Identity) -> Self {
        Self {
            initial_state,
            subscriber_id,
        }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, unsubscription: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(unsubscription.subscriber_id.identifier())?
            .commit()?
            .sign_sizeof(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream,
{
    async fn wrap(&mut self, unsubscription: &mut Wrap<'a>) -> Result<&mut Self> {
        self.join(unsubscription.initial_state)?
            .mask(unsubscription.subscriber_id.identifier())?
            .commit()?
            .sign(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for unsubscription message decoding
pub(crate) struct Unwrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The [`Identifier`] of the subscriber
    subscriber_id: Identifier,
}

impl<'a> Unwrap<'a> {
    /// Creates a new [`Unwrap`] struct for an unsubscription message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    pub(crate) fn new(initial_state: &'a mut Spongos) -> Self {
        Self {
            initial_state,
            subscriber_id: Identifier::default(),
        }
    }

    /// Returns a reference to the [`Identifier`] of the subscriber
    pub(crate) fn subscriber_identifier(&self) -> &Identifier {
        &self.subscriber_id
    }

    /// Consumes the [`Unwrap`], returning the [`Identifier`] of the subscriber
    pub(crate) fn into_subscriber_identifier(self) -> Identifier {
        self.subscriber_id
    }
}

#[async_trait(?Send)]
impl<'a, IS> ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, unsubscription: &mut Unwrap<'a>) -> Result<&mut Self> {
        self.join(unsubscription.initial_state)?
            .mask(&mut unsubscription.subscriber_id)?
            .commit()?
            .verify(&unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}
