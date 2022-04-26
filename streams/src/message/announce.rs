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
            Absorb,
            Commit,
        },
        io,
        types::Uint8,
    },
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

// Local

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     Result,
// };

// use iota_streams_ddml::{
//     command::*,
//     io,
//     types::*,
// };

pub(crate) struct Wrap<'a> {
    user_id: &'a Identity,
}

impl<'a> Wrap<'a> {
    pub(crate) fn new(user_id: &'a Identity) -> Self {
        Self { user_id }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, announcement: &Wrap<'a>) -> Result<&mut Self> {
        self.sizeof(&announcement.user_id.to_identifier())
            .await?
            .sign_sizeof(&announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, OS> ContentWrap<Wrap<'a>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    async fn wrap(&mut self, announcement: &mut Wrap<'a>) -> Result<&mut Self> {
        self.wrap(&mut announcement.user_id.to_identifier())
            .await?
            .sign(&mut announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Unwrap {
    author_id: Identifier,
}

impl Default for Unwrap {
    fn default() -> Self {
        let author_id = Default::default();
        Self { author_id }
    }
}

impl Unwrap {
    fn new() -> Self {
        Self::default()
    }

    pub(crate) fn author_id(self) -> Identifier {
        self.author_id
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentUnwrap<Unwrap> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, announcement: &mut Unwrap) -> Result<&mut Self> {
        self.unwrap(&mut announcement.author_id)
            .await?
            .verify(&mut announcement.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}
