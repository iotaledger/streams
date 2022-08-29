//! `Announce` message _wrapping_ and _unwrapping_.
//!
//! The `Announce` message is the _genesis_ message of a Stream.
//!
//! It announces the stream owner's identifier. The `Announce` message is similar to
//! a self-signed certificate in a conventional PKI.
//!
//! ```ddml
//! message Announce {
//!     absorb           u8     identifier[32];
//!     absorb           u8     flags;
//!     commit;
//!     squeeze          u8     hash[64];
//!     ed25519(hash)           sig;
//! }
//! ```

// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
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
    PRP,
};

// Local

pub(crate) struct Wrap<'a> {
    user_id: &'a Identity,
    topic: &'a Topic,
}

impl<'a> Wrap<'a> {
    pub(crate) fn new(user_id: &'a Identity, topic: &'a Topic) -> Self {
        Self { user_id, topic }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, announcement: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(&announcement.user_id.to_identifier())?
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
        self.mask(&announcement.user_id.to_identifier())?
            .mask(announcement.topic)?
            .sign(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Unwrap {
    author_id: Identifier,
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
    pub(crate) fn author_id(&self) -> &Identifier {
        &self.author_id
    }

    pub(crate) fn topic(&self) -> &Topic {
        &self.topic
    }

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
