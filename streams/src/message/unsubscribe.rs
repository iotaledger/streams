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
use async_trait::async_trait;
use anyhow::Result;

// IOTA
use crypto::signatures::ed25519;

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            wrap, unwrap, Commit, Join,
        },
        io,
    },
    Spongos,
    PRP,
};
use LETS::{
    id::{Identity, Identifier},
    message::{
        ContentSizeof,
        ContentWrap,
        ContentUnwrap, ContentSignSizeof, ContentSign, ContentVerify,
    },
};

// Local

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     sponge::prp::PRP,
//     Result,
// };
// use iota_streams_ddml::{
//     command::*,
//     io,
//     link_store::{
//         EmptyLinkStore,
//         LinkStore,
//     },
//     types::*,
// };

struct Wrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    subscriber_id: &'a Identity,
}

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<Wrap<'a, F>> for sizeof::Context {
    async fn sizeof(&mut self, unsubscription: &Wrap<'a, F>) -> Result<&mut Self> {
        self.sizeof(&unsubscription.subscriber_id.to_identifier())
            .await?
            .commit()?
            .sign_sizeof(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, OS> ContentWrap<Wrap<'a, F>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    async fn wrap(&mut self, unsubscription: &mut Wrap<'a, F>) -> Result<&mut Self> {
        self.join(unsubscription.initial_state)?
            .wrap(&mut unsubscription.subscriber_id.to_identifier())
            .await?
            .commit()?
            .sign(unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    subscriber_id: Identifier,
}

#[async_trait(?Send)]
impl<'a, F, IS> ContentUnwrap<Unwrap<'a, F>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, unsubscription: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        self.join(unsubscription.initial_state)?
            .unwrap(&mut unsubscription.subscriber_id)
            .await?
            .commit()?
            .verify(&unsubscription.subscriber_id)
            .await?;
        Ok(self)
    }
}