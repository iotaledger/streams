//! `Subscribe` message _wrapping_ and _unwrapping_.
//!
//! `Subscribe` messages are published by a user willing to become a subscriber to this channel.
//!
//! They contain the subscriber's identifier that will be used in keyload
//! messages to encrypt session keys.
//!
//! Subscriber's Identifier is encrypted with the `unsubscribe_key`
//! which in turn is encapsulated for channel owner using owner's Ed25519 public
//! key. The resulting spongos state will be used for unsubscription.
//! Subscriber must trust channel owner's Ed25519 public key in order to
//! maintain privacy.
//!
//!
//! ```ddml
//! message Subscribe {
//!     join(spongos);
//!     x25519(pub/priv_key)    u8      x25519_auth_pubkey[32];
//!     commit;
//!     mask                    u8      identifier;
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
use crypto::keys::x25519;

// Streams
use lets::{
    id::{Identifier, Identity},
    message::{ContentSign, ContentSignSizeof, ContentSizeof, ContentUnwrap, ContentVerify, ContentWrap},
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Join, Mask, X25519},
        io,
        types::NBytes,
    },
    error::Result,
    Spongos,
};

/// A struct that holds references needed for subscription message encoding
pub(crate) struct Wrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// Unique key used for unsubscription request
    unsubscribe_key: [u8; 32],
    /// The [`Identity`] of the subscriber
    subscriber_id: &'a Identity,
    /// The authors [`x25519::PublicKey`]
    author_ke_pk: &'a x25519::PublicKey,
}

impl<'a> Wrap<'a> {
    /// Creates a new [`Wrap`] struct for a subscription message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `unsubscribe_key`: A unique key for unsubscribing later.
    /// * `subscriber_id`: The [`Identity`] of the subscriber.
    /// * `author_ke_pk`: The author's public exchange key
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
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
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, subscription: &Wrap<'a>) -> Result<&mut Self> {
        self.x25519(subscription.author_ke_pk, NBytes::new(subscription.unsubscribe_key))?
            .mask(subscription.subscriber_id.identifier())?
            .sign_sizeof(subscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream,
{
    async fn wrap(&mut self, subscription: &mut Wrap<'a>) -> Result<&mut Self> {
        self.join(subscription.initial_state)?
            .x25519(subscription.author_ke_pk, NBytes::new(subscription.unsubscribe_key))?
            .mask(subscription.subscriber_id.identifier())?
            .sign(subscription.subscriber_id)
            .await?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for subscription message decoding
pub(crate) struct Unwrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The subscriber's unique unsubscribe key
    unsubscribe_key: [u8; 32],
    /// The [`Identifier`] of the subscriber
    subscriber_identifier: Identifier,
    /// The author's [x25519::SecretKey`]
    author_ke_sk: &'a x25519::SecretKey,
}

impl<'a> Unwrap<'a> {
    /// Creates a new [`Unwrap`] struct for a subscription message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `author_ke_sk`: The author's secret exchange key
    pub(crate) fn new(initial_state: &'a mut Spongos, author_ke_sk: &'a x25519::SecretKey) -> Self {
        Self {
            initial_state,
            unsubscribe_key: Default::default(),
            subscriber_identifier: Default::default(),
            author_ke_sk,
        }
    }

    /// Returns a reference to the [`Identifier`] of the subsriber
    pub(crate) fn subscriber_identifier(&self) -> &Identifier {
        &self.subscriber_identifier
    }

    /// Consumes the [`Unwrap`], returning the [`Identifier`] of the subscriber
    pub(crate) fn into_subscriber_identifier(self) -> Identifier {
        self.subscriber_identifier
    }
}

#[async_trait(?Send)]
impl<'a, IS> ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, subscription: &mut Unwrap<'a>) -> Result<&mut Self> {
        self.join(subscription.initial_state)?
            .x25519(
                subscription.author_ke_sk,
                NBytes::new(&mut subscription.unsubscribe_key),
            )?
            .mask(&mut subscription.subscriber_identifier)?
            .verify(&subscription.subscriber_identifier)
            .await?;
        Ok(self)
    }
}
