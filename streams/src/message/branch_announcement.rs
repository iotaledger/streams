//! `BranchAnnounce` message _wrapping_ and _unwrapping_.
//!
//! The `BranchAnnounce` message creates a new branch in a Stream.
//!
//! It announces the [`Topic`] for the new branch, as well as informs of the previous branch topic
//! the new branch is being generated from.
//!
//! ```ddml
//! message BranchAnnounce {
//!     join(spongos);
//!     mask             u8     identifier;
//!     mask             u8     new_topic;
//!     mask             u8     previous_topic;
//!     commit;
//!     squeeze          u8     hash[64];
//!     ed25519(hash)           sig;
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
    message::{ContentSign, ContentSignSizeof, ContentSizeof, ContentUnwrap, ContentVerify, ContentWrap, Topic},
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

/// A struct that holds references needed for branch announcement message encoding
pub(crate) struct Wrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The [`Identity`] of the publisher
    user_id: &'a Identity,
    /// The new branch [`Topic`]
    new_topic: &'a Topic,
}

impl<'a> Wrap<'a> {
    /// Creates a new [`Wrap`] struct for a branch announcement message
    ///
    /// # Arguments
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `user_id`: The [`Identity`] of the publisher
    /// * `new_topic`: the new branch [`Topic`]
    pub(crate) fn new(initial_state: &'a mut Spongos, user_id: &'a Identity, new_topic: &'a Topic) -> Self {
        Self {
            initial_state,
            user_id,
            new_topic,
        }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, announcement: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(announcement.user_id.identifier())?
            .mask(announcement.new_topic)?
            .sign_sizeof(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream,
{
    async fn wrap(&mut self, announcement: &mut Wrap<'a>) -> Result<&mut Self> {
        self.join(announcement.initial_state)?
            .mask(announcement.user_id.identifier())?
            .mask(announcement.new_topic)?
            .sign(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for branch announcement message decoding
pub(crate) struct Unwrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// The new branch [`Topic`]
    new_topic: Topic,
}

impl<'a> Unwrap<'a> {
    /// Cretes a new [`Unwrap`] struct for a branch announcement message
    ///
    /// # Arguments
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    pub(crate) fn new(initial_state: &'a mut Spongos) -> Self {
        Self {
            initial_state,
            new_topic: Topic::default(),
        }
    }

    /// Returns a refernce to the new branch [`Topic`]
    pub(crate) fn new_topic(&self) -> &Topic {
        &self.new_topic
    }

    /// Consumes the [`Unwrap`], returning the new branch [`Topic`]
    pub(crate) fn into_new_topic(self) -> Topic {
        self.new_topic
    }
}

#[async_trait(?Send)]
impl<'a, IS> ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, announcement: &mut Unwrap) -> Result<&mut Self> {
        let mut author_id = Identifier::default();
        self.join(announcement.initial_state)?
            .mask(&mut author_id)?
            .mask(&mut announcement.new_topic)?
            .verify(&author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}
