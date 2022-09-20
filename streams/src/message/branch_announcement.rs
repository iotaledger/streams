//! `BranchAnnounce` message _wrapping_ and _unwrapping_.
//!
//! The `BranchAnnounce` message creates a new branch in a Stream.
//!
//! It announces the topic for the new branch, as well as informs of the previous branch topic the
//! new branch is being generated from.
//!
//! ```ddml
//! message BranchAnnounce {
//!     join(Spongos);
//!     mask             u8     identifier[32];
//!     mask             u8     topic;
//!     mask             u8     previous_topic;
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
        commands::{sizeof, unwrap, wrap, Commit, Join, Mask},
        io,
    },
    Spongos,
};

// Local

pub(crate) struct Wrap<'a> {
    initial_state: &'a mut Spongos,
    user_id: &'a Identity,
    new_topic: &'a Topic,
}

impl<'a> Wrap<'a> {
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
        self.mask(&announcement.user_id.to_identifier())?
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
            .mask(&announcement.user_id.to_identifier())?
            .mask(announcement.new_topic)?
            .sign(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a> {
    initial_state: &'a mut Spongos,
    new_topic: Topic,
}

impl<'a> Unwrap<'a> {
    pub(crate) fn new(initial_state: &'a mut Spongos) -> Self {
        Self {
            initial_state,
            new_topic: Topic::default(),
        }
    }

    pub(crate) fn new_topic(&self) -> &Topic {
        &self.new_topic
    }

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
