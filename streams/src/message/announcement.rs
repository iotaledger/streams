//! `Announcement` message _wrapping_ and _unwrapping_.
//!
//! The `Announcement` message is the _genesis_ message of a Stream.
//!
//! It announces the stream owner's identifier. The `Announcement` message is similar to
//! a self-signed certificate in a conventional PKI.
//!
//! ```ddml
//! message Announcement {
//!     mask             u8     identifier;
//!     mask             u8     topic;
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
        commands::{sizeof, unwrap, wrap, Commit, Mask},
        io,
    },
    error::Result,
    PRP,
};

// Local

/// A struct that holds references needed for announcement message encoding
pub(crate) struct Wrap<'a> {
    /// The [`Identity`] of the sender of the message
    user_id: &'a Identity,
    /// The [`Topic`] of the base branch of the stream
    topic: &'a Topic,
}

impl<'a> Wrap<'a> {
    /// Creates a new [`Wrap`] struct for an announcement message
    ///
    /// # Arguments
    /// * `user_id`: The [`Identity`] of the sender
    /// * `topic`: The base branch [`Topic`] for the stream
    pub(crate) fn new(user_id: &'a Identity, topic: &'a Topic) -> Self {
        Self { user_id, topic }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, announcement: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(announcement.user_id.identifier())?
            .mask(announcement.topic)?
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
        self.mask(announcement.user_id.identifier())?
            .mask(announcement.topic)?
            .sign(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for announcement message decoding
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Unwrap {
    /// The public [`Identifier`] of the stream author
    author_id: Identifier,
    /// The base branch [`Topic`] of the stream
    topic: Topic,
}

impl Default for Unwrap {
    fn default() -> Self {
        let author_id = Default::default();
        let topic = Default::default();
        Self { author_id, topic }
    }
}

impl Unwrap {
    /// Returns a reference to the [`Identifier`] of the author.
    pub(crate) fn author_id(&self) -> &Identifier {
        &self.author_id
    }
    /// Returns a reference to the base branch [`Topic`] of the stream.
    pub(crate) fn topic(&self) -> &Topic {
        &self.topic
    }
    /// Consumes the [`Unwrap`], returning the [`Identifier`] of the author.
    pub(crate) fn into_author_id(self) -> Identifier {
        self.author_id
    }
}

#[async_trait(?Send)]
impl<IS, F> ContentUnwrap<Unwrap> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, announcement: &mut Unwrap) -> Result<&mut Self> {
        self.mask(&mut announcement.author_id)?
            .mask(&mut announcement.topic)?
            .verify(&announcement.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}
