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

use failure::bail;

use iota_mam_core::{signature::mss, key_encapsulation::ntru, psk, prng};
use iota_mam_protobuf3::{command::*, io, types::*};
use crate::Result;
use crate::core::HasLink;
use crate::core::msg;

/// Type of `SignedPacket` message content.
pub const TYPE: &str = "MAM9CHANNEL9SIGNEDPACKET";

pub struct ContentWrap<'a, Link> where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Trytes,
    pub(crate) masked_payload: &'a Trytes,
    pub(crate) mss_sk: &'a mss::PrivateKey,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<'a, Link, Store> msg::ContentWrap<Store> for ContentWrap<'a, Link> where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        let store = EmptyLinkStore::<<Link as HasLink>::Rel, ()>::default();
        ctx
            .join(&store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?
        ;
        //TODO: Is both public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(&self, store: &Store, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        ctx
            .join(store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?
        ;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Trytes,
    pub(crate) masked_payload: Trytes,
    pub(crate) mss_pk: mss::PublicKey,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<Link> ContentUnwrap<Link> where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Trytes::default(),
            masked_payload: Trytes::default(),
            mss_pk: mss::PublicKey::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Link, Store> msg::ContentUnwrap<Store> for ContentUnwrap<Link> where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream>(&mut self, store: &Store, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        ctx
            .join(store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .mssig(&mut self.mss_pk, MssHashSig)?
        ;
        Ok(ctx)
    }
}
