//! Customize Author with default implementation for use over the Tangle.

use anyhow::Result;
use std::str::FromStr;

use super::*;
use crate::api::author::AuthorT;
use iota_streams_app::message::HasLink as _;

use iota_streams_core_edsig::{key_exchange::x25519};
use iota_streams_core::{
    prng,
};

type AuthorImp = AuthorT<DefaultF, Address, Store, LinkGen>;

/// Author type.
pub struct Author {
    imp: AuthorImp,
}

impl Author {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(seed: &str) -> Self {
        let nonce = "TANGLEAUTHORNONCE".as_bytes().to_vec();
        Self {
            imp: AuthorT::gen(
                Store::default(),
                LinkGen::default(),
                prng::dbg_init_str(seed),
                nonce,
            ),
        }
    }

    /// Channel app instance.
    pub fn channel_address(&self) -> &ChannelAddress {
        &self.imp.appinst.appinst
    }

    /// Announce creation of a new Channel.
    pub fn announce(&mut self) -> Result<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    /// Create a new keyload for a list of subscribers.
    pub fn share_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ke_pks: &Vec<x25519::PublicKeyWrap>) -> Result<Message> {
        self.imp
            .share_keyload(link_to.rel(), psk_ids, ke_pks, MsgInfo::Keyload)
    }

    /// Create keyload for all subscribed subscribers.
    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<Message> {
        self.imp.share_keyload_for_everyone(link_to.rel(), MsgInfo::Keyload)
    }

    /// Create a signed packet.
    pub fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<Message> {
        self.imp
            .sign_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::SignedPacket)
    }

    /// Create a tagged packet.
    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<Message> {
        self.imp
            .tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket)
    }

    /// Unwrap tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    /// Subscribe a new subscriber.
    pub fn unwrap_subscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_subscribe(preparsed, MsgInfo::Subscribe)
    }

    /*
    /// Unsubscribe a subscriber
    pub fn unwrap_unsubscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_unsubscribe(preparsed, MsgInfo::Unsubscribe)
    }
     */
}
