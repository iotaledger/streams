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
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};
use crate::Result;
use crate::core::HasLink;

/// Type of `SignedPacket` message content.
pub const TYPE: &str = "MAM9CHANNEL9SIGNEDPACKET";

pub struct ContentWrap<'a, RelLink: 'a, Store: 'a> {
    pub(crate) store: &'a Store,
    pub(crate) link: &'a RelLink,
    pub(crate) public_payload: &'a Trytes,
    pub(crate) masked_payload: &'a Trytes,
    pub(crate) mss_sk: &'a mss::PrivateKey,
}

impl<'a, RelLink: 'a, Store: 'a> ContentWrap<'a, RelLink, Store> where
    RelLink: Eq + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub(crate) fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        ctx
            .join(self.store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?
        ;
        //TODO: Is both public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }
    pub(crate) fn wrap<'c, OS: io::OStream>(&self, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        ctx
            .join(self.store, self.link)?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .mssig(self.mss_sk, MssHashSig)?
        ;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<'a, RelLink, Store> {
    pub(crate) store: &'a Store,
    pub(crate) link: RelLink,
    pub(crate) public_payload: Trytes,
    pub(crate) masked_payload: Trytes,
    pub(crate) mss_pk: mss::PublicKey,
}

impl<'a, RelLink: 'a, Store: 'a> ContentUnwrap<'a, RelLink, Store> where
    RelLink: Eq + Default + SkipFallback,
    Store: LinkStore<RelLink>,
{
    pub fn new(store: &'a Store) -> Self {
        Self {
            store: store,
            link: RelLink::default(),
            public_payload: Trytes::default(),
            masked_payload: Trytes::default(),
            mss_pk: mss::PublicKey::default(),
        }
    }

    pub(crate) fn unwrap<'c, IS: io::IStream>(&mut self, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        ctx
            .join(self.store, &mut self.link)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .mssig(&mut self.mss_pk, MssHashSig)?
        ;
        Ok(ctx)
    }
}
