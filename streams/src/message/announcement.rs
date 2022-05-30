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
//!     squeeze          u8     hash[32];
//!     ed25519(hash)           sig;
//! }
//! ```

// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
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
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask},
        io,
        types::{Uint32, Uint64},
    },
    PRP,
};

// Local

pub(crate) struct Wrap<'a> {
    user_id: &'a Identity,
    retention_policy: u32,
    genesis_ts: u64,
}

impl<'a> Wrap<'a> {
    pub(crate) fn new(user_id: &'a Identity, retention_policy: u32, genesis_ts: u64) -> Self {
        Self {
            user_id,
            retention_policy,
            genesis_ts,
        }
    }
}

#[async_trait]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, announcement: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(&announcement.user_id.to_identifier())?
            .absorb(Uint32::new(announcement.retention_policy))?
            .absorb(Uint64::new(announcement.genesis_ts))?
            // TODO: REMOVE ONCE KE IS ENCAPSULATED WITHIN IDENTITY
            .absorb(
                &announcement
                    .user_id
                    ._ke_sk()
                    .expect("the author of an Stream must have an identity capable of key exchange")
                    .public_key(),
            )?
            .sign_sizeof(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream + Send,
{
    async fn wrap(&mut self, announcement: &mut Wrap<'a>) -> Result<&mut Self> {
        self.mask(&announcement.user_id.to_identifier())?
            .absorb(Uint32::new(announcement.retention_policy))?
            .absorb(Uint64::new(announcement.genesis_ts))?
            // TODO: REMOVE ONCE KE IS ENCAPSULATED WITHIN IDENTITY
            .absorb(
                &announcement
                    .user_id
                    ._ke_sk()
                    .expect("the author of an Stream must have an identity capable of key exchange")
                    .public_key(),
            )?
            .sign(announcement.user_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Unwrap {
    author_id: Identifier,
    retention_policy: u32,
    genesis_ts: u64,
    // TODO: REMOVE ONCE KE IS ENCAPSULATED WITHIN IDENTITY
    author_ke_pk: x25519::PublicKey,
}

impl Default for Unwrap {
    fn default() -> Self {
        let author_id = Default::default();
        let retention_policy = Default::default();
        let genesis_ts = Default::default();
        let author_ke_pk = x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]);
        Self {
            author_id,
            retention_policy,
            genesis_ts,
            author_ke_pk,
        }
    }
}

impl Unwrap {
    pub(crate) fn author_id(self) -> Identifier {
        self.author_id
    }

    pub(crate) fn retention_policy(self) -> u32 {
        self.retention_policy
    }

    pub(crate) fn genesis_ts(self) -> u64 {
        self.genesis_ts
    }

    // #[deprecated = "to be removed once ke is encapsulated within identity"]
    pub(crate) fn author_ke_pk(self) -> x25519::PublicKey {
        self.author_ke_pk
    }
}

#[async_trait]
impl<IS, F> ContentUnwrap<Unwrap> for unwrap::Context<IS, F>
where
    F: PRP + Send,
    IS: io::IStream + Send,
{
    async fn unwrap(&mut self, announcement: &mut Unwrap) -> Result<&mut Self> {
        let mut retention_policy = Uint32::default();
        let mut genesis_ts = Uint64::default();
        self.mask(&mut announcement.author_id)?
            .absorb(&mut retention_policy)?
            .absorb(&mut genesis_ts)?
            .absorb(&mut announcement.author_ke_pk)?
            .verify(&announcement.author_id)
            .await?
            .commit()?;
        announcement.retention_policy = retention_policy.inner();
        announcement.genesis_ts = genesis_ts.inner();
        Ok(self)
    }
}
