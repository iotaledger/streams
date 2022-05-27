//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```ddml
//! message Unsubscribe {
//!     join link msgid;
//!     absorb u8 ed25519pk[32];
//!     commit;
//!     squeeze external byte hash[32];
//!     mssig(hash) sig;
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Subscribe` message published by the subscriber.
//!
//! * `ed25519pk` -- subscriber's Ed25519 public key.
//!
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with the senders private key.
// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
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
    Spongos,
};

// Local

pub(crate) struct Wrap<'a> {
    initial_state: &'a mut Spongos,
    subscriber_id: &'a Identity,
}

impl<'a> Wrap<'a> {
    pub(crate) fn new(initial_state: &'a mut Spongos, subscriber_id: &'a Identity) -> Self {
        Self {
            initial_state,
            subscriber_id,
        }
    }
}

#[async_trait]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, unsubscription: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(&unsubscription.subscriber_id.to_identifier())?
            .commit()?
            .sign_sizeof(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

#[async_trait]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream + Send,
{
    async fn wrap(&mut self, unsubscription: &mut Wrap<'a>) -> Result<&mut Self> {
        self.join(unsubscription.initial_state)?
            .mask(&unsubscription.subscriber_id.to_identifier())?
            .commit()?
            .sign(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a> {
    initial_state: &'a mut Spongos,
    subscriber_id: Identifier,
}

impl<'a> Unwrap<'a> {
    pub(crate) fn new(initial_state: &'a mut Spongos) -> Self {
        Self {
            initial_state,
            subscriber_id: Identifier::default(),
        }
    }

    pub(crate) fn subscriber_identifier(&self) -> Identifier {
        self.subscriber_id
    }
}

#[async_trait]
impl<'a, IS> ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream + Send,
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
