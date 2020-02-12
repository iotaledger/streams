//! `ChangeKey` message content. This message is published by channel author.
//! The message is linked to either `Announce` or `ChangeKey` message.
//!
//! ```pb3
//! message ChangeKey {
//!     join link msgid;
//!     absorb tryte msspk[81];
//!     commit;
//!     squeeze external tryte hash[78];
//!     mssig(hash) sig_with_msspk;
//!     mssig(hash) sig_with_linked_msspk;
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the message containing a trusted MSS public key.
//! This key is used to derive trust relationship to the `msspk` public key.
//!
//! * `msspk` -- a new MSS public key.
//!
//! * `hash` -- message hash value to be signed.
//!
//! * `sig_with_msspk` -- signature generated with the MSS private key corresponding
//! to the public key contained in `msspk` field -- proof of knowledge of private key.
//!
//! * `sig_with_linked_msspk` -- signature generated with the MSS private key
//! corresponding to the *trusted* public key contained in the linked message.
//!

use failure::bail;

use iota_mam_core::{signature::mss, key_encapsulation::ntru};
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};
use crate::Result;
use crate::core::HasLink;
use crate::core::msg;

/// Type of `ChangeKey` message content.
pub const TYPE: &str = "MAM9CHANNEL9CHANGEKEY";

pub struct ContentWrap<'a, RelLink: 'a, Store: 'a> {
    pub(crate) store: &'a Store,
    pub(crate) link: &'a RelLink,
    pub(crate) mss_pk: &'a mss::PublicKey,
    pub(crate) mss_sk: &'a mss::PrivateKey,
    pub(crate) mss_linked_sk: &'a mss::PrivateKey,
}

impl<'a, RelLink: 'a, Store: 'a> ContentWrap<'a, RelLink, Store> where
    RelLink: Eq + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        let hash = External(Mac(mss::HASH_SIZE));
        ctx
            .join(self.store, self.link)?
            .absorb(self.mss_pk)?
            .commit()?
            .squeeze(&hash)?
            .mssig(self.mss_sk, &hash)?
            .mssig(self.mss_linked_sk, &hash)?
        ;
        Ok(ctx)
    }
    pub fn wrap<'c, OS: io::OStream>(&self, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        let mut hash = External(NTrytes::zero(mss::HASH_SIZE));
        ctx
            .join(self.store, self.link)?
            .absorb(self.mss_pk)?
            .commit()?
            .squeeze(&mut hash)?
            .mssig(self.mss_sk, &hash)?
            .mssig(self.mss_linked_sk, &hash)?
        ;
        //TODO: Order: first mss_sk then mss_linked_sk or vice versa?
        Ok(ctx)
    }
}

impl<'c, RelLink: 'c, Store: 'c> msg::ContentWrap for ContentWrap<'c, RelLink, Store> where
    RelLink: Eq + SkipFallback,
    Store: LinkStore<RelLink>,
{
    fn sizeof2<'a>(&self, ctx: &'a mut sizeof::Context) -> Result<&'a mut sizeof::Context> {
        self.sizeof(ctx)
    }

    fn wrap2<'a, OS: io::OStream>(&'a self, ctx: &'a mut wrap::Context<OS>) -> Result<&'a mut wrap::Context<OS>> {
        self.wrap(ctx)
    }
}

pub struct ContentUnwrap<'a, RelLink, Store> {
    pub(crate) store: &'a Store,
    pub(crate) link: RelLink,
    pub(crate) mss_pk: mss::PublicKey,
    pub(crate) mss_linked_pk: &'a mss::PublicKey,
}

impl<'a, RelLink: 'a, Store: 'a> ContentUnwrap<'a, RelLink, Store> where
    RelLink: Eq + Default + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub fn new(store: &'a Store, mss_linked_pk: &'a mss::PublicKey) -> Self {
        Self {
            store: store,
            link: RelLink::default(),
            mss_pk: mss::PublicKey::default(),
            mss_linked_pk: mss_linked_pk,
        }
    }

    pub(crate) fn unwrap<'c, IS: io::IStream>(&mut self, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        let mut hash = External(NTrytes::zero(mss::HASH_SIZE));
        ctx
            .join(self.store, &mut self.link)?
            .absorb(&mut self.mss_pk)?
            .commit()?
            .squeeze(&mut hash)?
            .mssig(&self.mss_pk, &hash)?
            .mssig(self.mss_linked_pk, &hash)?
        ;
        //TODO: Lookup mss_linked_pk first and verify?
        //Or recover mss_linked_pk and lookup info in the store and verify?
        Ok(ctx)
    }
}
