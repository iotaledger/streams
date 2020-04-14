//! `SignedPacket` message content. The message may be linked to any other message
//! in the channel. It contains both plain and masked payloads. The message can only
//! be signed and published by channel owner. Channel owner must firstly publish
//! corresponding public key certificate in either `Announce` or `ChangeKey` message.
//!
//! ```pb3
//! message SignedPacket {
//!     join link msgid;
//!     absorb trytes public_payload;
//!     mask trytes masked_payload;
//!     commit;
//!     squeeze external tryte hash[78];
//!     mssig(hash) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `msgid` -- link to the base message.
//!
//! * `public_payload` -- public part of payload.
//!
//! * `masked_payload` -- masked part of payload.
//!
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with one of channel owner's private key.
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

/// Type of `SignedPacket` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9SIGNEDPACKET";

pub struct ContentWrap<'a, TW, F, P, Link>
where
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Trytes<TW>,
    pub(crate) masked_payload: &'a Trytes<TW>,
    pub(crate) mss_sk: &'a mss::PrivateKey<TW, P>,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, TW, F, P, Link, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, F, P, Link>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Fallible<&'c mut sizeof::Context<TW, F>> {
        let store = EmptyLinkStore::<TW, F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?;
        //TODO: Is both public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>> {
        ctx.join(store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<TW, F, P, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Trytes<TW>,
    pub(crate) masked_payload: Trytes<TW>,
    pub(crate) mss_pk: mss::PublicKey<TW, P>,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<TW, F, P, Link> ContentUnwrap<TW, F, P, Link>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Trytes::<TW>::default(),
            masked_payload: Trytes::<TW>::default(),
            mss_pk: mss::PublicKey::<TW, P>::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F, P, Link, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<TW, F, P, Link>
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
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .mssig(&mut self.mss_pk, MssHashSig)?;
        Ok(ctx)
    }
}
