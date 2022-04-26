//! `Subscribe` message _wrapping_ and _unwrapping_.
//!
//! `Subscribe` messages are published by a user willing to become a subscriber to this channel.
//!
//! They contain the subscriber's identifier that will be used in keyload
//! messages to encrypt session keys.
//!
//! Subscriber's Ed25519 public key is encrypted with the `unsubscribe_key`
//! which in turn is encapsulated for channel owner using owner's Ed25519 public
//! key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's Ed25519 public key in order to
//! maintain privacy.
//!
//! Channel Owner must maintain the resulting spongos state associated to the Subscriber's
//! Ed25519 public key.
//!
//! ```ddml
//! message Subscribe {
//!     skip                    link    msgid;
//!     join(msgid);
//!     x25519(pub/priv_key)    u8      x25519_auth_pubkey[32];
//!     commit;
//!     mask                    u8      unsubscribe_key[32];
//!     mask                    u8      pk[32];
//!     commit;
//!     squeeze external        u8      hash[64];
//!     ed25519(hash)           u8      signature[64];
//! }
//! ```
// Rust
use alloc::boxed::Box;
use core::convert::TryInto;

// 3rd_party
use anyhow::Result;
use async_trait::async_trait;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Join,
            X25519,
        },
        io,
        types::NBytes,
    },
    Spongos,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
    },
    message::{
        ContentSign,
        ContentSignSizeof,
        ContentSizeof,
        ContentUnwrap,
        ContentVerify,
        ContentWrap,
    },
};
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

pub(crate) struct Wrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    unsubscribe_key: [u8; 32],
    subscriber_id: &'a Identity,
    author_ke_pk: &'a x25519::PublicKey,
}

impl<'a, F> Wrap<'a, F> {
    pub(crate) fn new(
        initial_state: &'a mut Spongos<F>,
        unsubscribe_key: [u8; 32],
        subscriber_id: &'a Identity,
        author_ke_pk: &'a x25519::PublicKey,
    ) -> Self {
        Self {
            initial_state,
            unsubscribe_key,
            subscriber_id,
            author_ke_pk,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<Wrap<'a, F>> for sizeof::Context {
    async fn sizeof(&mut self, subscription: &Wrap<'a, F>) -> Result<&mut Self> {
        self.x25519(subscription.author_ke_pk, &NBytes::new(&subscription.unsubscribe_key))?
            .sizeof(&subscription.subscriber_id.to_identifier())
            .await?
            .sign_sizeof(subscription.subscriber_id)
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
    async fn wrap(&mut self, subscription: &mut Wrap<'a, F>) -> Result<&mut Self> {
        self.join(subscription.initial_state)?
            .x25519(subscription.author_ke_pk, &NBytes::new(&subscription.unsubscribe_key))?
            .wrap(&mut subscription.subscriber_id.to_identifier())
            .await?
            .sign(subscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    unsubscribe_key: [u8; 32],
    subscriber_id: Identifier,
    author_ke_sk: &'a x25519::SecretKey,
}

impl<'a, F> Unwrap<'a, F>
{
    pub(crate) fn new(initial_state: &'a mut Spongos<F>, author_ke_sk: &'a x25519::SecretKey) -> Self {
        Self {
            initial_state,
            unsubscribe_key: Default::default(),
            subscriber_id: Default::default(),
            author_ke_sk,
        }
    }

    pub(crate) fn subscriber_id(&self) -> Identifier {
        self.subscriber_id
    }
}

#[async_trait(?Send)]
impl<'a, F, IS> ContentUnwrap<Unwrap<'a, F>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, subscription: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        self.join(subscription.initial_state)?
            .x25519(
                subscription.author_ke_sk,
                &mut NBytes::new(&mut subscription.unsubscribe_key),
            )?
            .unwrap(&mut subscription.subscriber_id)
            .await?
            .verify(&subscription.subscriber_id)
            .await?;
        Ok(self)
    }
}
