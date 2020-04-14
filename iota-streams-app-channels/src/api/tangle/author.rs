//! Customize Author with default implementation for use over the Tangle.

use failure::Fallible;
use std::str::FromStr;

use super::*;
use crate::api::author::AuthorT;
use iota_streams_app::message::HasLink as _;

use iota_streams_core::{
    prng,
    tbits::Tbits,
};

type AuthorImp = AuthorT<DefaultTW, DefaultF, DefaultP, Address, Store, LinkGen>;

/// Author type.
pub struct Author {
    imp: AuthorImp,
}

impl Author {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(seed: &str, mss_height: usize, with_ntru: bool) -> Self {
        let nonce = Tbits::from_str("TANGLEAUTHOR").unwrap();
        Self {
            imp: AuthorT::gen(
                Store::default(),
                LinkGen::default(),
                prng::dbg_init_str(seed),
                &nonce,
                mss_height,
                with_ntru,
            ),
        }
    }

    /// Channel app instance.
    pub fn channel_address(&self) -> &ChannelAddress {
        &self.imp.appinst.appinst
    }

    /// Announce creation of a new Channel.
    pub fn announce(&mut self) -> Fallible<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    /// Change keys, attach message to `link_to`.
    pub fn change_key(&mut self, link_to: &Address) -> Fallible<Message> {
        self.imp.change_key(link_to.rel(), MsgInfo::ChangeKey)
    }

    /// Create a new keyload for a list of subscribers.
    pub fn share_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ntru_pkids: &NtruPkids) -> Fallible<Message> {
        self.imp
            .share_keyload(link_to.rel(), psk_ids, ntru_pkids, MsgInfo::Keyload)
    }

    /// Create keyload for all subscribed subscribers.
    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Fallible<Message> {
        self.imp.share_keyload_for_everyone(link_to.rel(), MsgInfo::Keyload)
    }

    /// Create a signed packet.
    pub fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Trytes,
        masked_payload: &Trytes,
    ) -> Fallible<Message> {
        self.imp
            .sign_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::SignedPacket)
    }

    /// Create a tagged packet.
    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Trytes,
        masked_payload: &Trytes,
    ) -> Fallible<Message> {
        self.imp
            .tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket)
    }

    /// Unwrap tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Fallible<(Trytes, Trytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    /// Subscribe a new subscriber.
    pub fn unwrap_subscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Fallible<()> {
        self.imp.handle_subscribe(preparsed, MsgInfo::Subscribe)
    }

    /// Unsubscribe a subscriber
    pub fn unwrap_unsubscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Fallible<()> {
        self.imp.handle_unsubscribe(preparsed, MsgInfo::Unsubscribe)
    }
}
