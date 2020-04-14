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

use failure::Fallible;
use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            BasicTbitWord,
            IntTbitWord,
            SpongosTbitWord,
        },
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `ChangeKey` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9CHANGEKEY";

pub struct ContentWrap<'a, TW, P, Link>
where
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) mss_sk: mss::PrivateKey<TW, P>,
    pub(crate) mss_linked_sk: &'a mss::PrivateKey<TW, P>,
    _phantom: std::marker::PhantomData<Link>,
}

impl<'a, TW, P, Link> ContentWrap<'a, TW, P, Link>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub fn new(
        link: &'a <Link as HasLink>::Rel,
        mss_sk: mss::PrivateKey<TW, P>,
        mss_linked_sk: &'a mss::PrivateKey<TW, P>,
    ) -> Self {
        Self {
            link: link,
            mss_sk: mss_sk,
            mss_linked_sk: mss_linked_sk,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW, F, P, Link, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, P, Link>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Fallible<&'c mut sizeof::Context<TW, F>> {
        // Store has no impact on wrapped size
        let store = EmptyLinkStore::<TW, F, <Link as HasLink>::Rel, ()>::default();
        let hash = External(Mac(P::HASH_SIZE));
        ctx.join(&store, self.link)?
            .absorb(self.mss_sk.public_key())?
            .commit()?
            .squeeze(&hash)?
            .mssig(&self.mss_sk, &hash)?
            .mssig(self.mss_linked_sk, &hash)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
        let mut hash = External(NTrytes::zero(P::HASH_SIZE));
        ctx.join(store, self.link)?
            .absorb(self.mss_sk.public_key())?
            .commit()?
            .squeeze(&mut hash)?
            .mssig(&self.mss_sk, &hash)?
            .mssig(self.mss_linked_sk, &hash)?;
        //TODO: Order: first mss_sk then mss_linked_sk or vice versa?
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, TW, P, Link>
where
    Link: HasLink,
{
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) mss_pk: mss::PublicKey<TW, P>,
    pub(crate) mss_linked_pk: &'a mss::PublicKey<TW, P>,
    _phantom: std::marker::PhantomData<Link>,
}

impl<'a, TW, P, Link> ContentUnwrap<'a, TW, P, Link>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Default,
{
    pub fn new(mss_linked_pk: &'a mss::PublicKey<TW, P>) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            mss_pk: mss::PublicKey::<TW, P>::default(),
            mss_linked_pk: mss_linked_pk,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW, F, P, Link, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<'a, TW, P, Link>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>> {
        let mut hash = External(NTrytes::zero(P::HASH_SIZE));
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.mss_pk)?
            .commit()?
            .squeeze(&mut hash)?
            .mssig(&self.mss_pk, &hash)?
            .mssig(self.mss_linked_pk, &hash)?;
        //TODO: Lookup mss_linked_pk first and verify?
        //Or recover mss_linked_pk and lookup info in the store and verify?
        Ok(ctx)
    }
}
