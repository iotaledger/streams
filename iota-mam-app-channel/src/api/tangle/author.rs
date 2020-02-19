//! Customize Author with default implementation for use over the Tangle.

use failure::Fallible;
use std::str::FromStr;

use super::*;
use crate::api::author::*;
use iota_mam_app::message::*;
use iota_mam_core::{key_encapsulation::ntru, prng, psk, trits::Trits};
use iota_mam_protobuf3::types::Trytes;

/// Author type.
pub struct Author {
    imp: AuthorT<Address, Store, LinkGen>,
}

impl Author {
    pub fn new(seed: &str, mss_height: usize, with_ntru: bool) -> Self {
        let nonce = Trits::from_str("TANGLEAUTHOR").unwrap();
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

    pub fn announce(&mut self) -> Fallible<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    pub fn change_key(&mut self, link_to: &Address) -> Fallible<Message> {
        self.imp.change_key(link_to.rel(), MsgInfo::ChangeKey)
    }

    pub fn share_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &psk::PskIds,
        ntru_pkids: &ntru::NtruPkids,
    ) -> Fallible<Message> {
        self.imp
            .share_keyload(link_to.rel(), psk_ids, ntru_pkids, MsgInfo::Keyload)
    }

    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Fallible<Message> {
        self.imp
            .share_keyload_for_everyone(link_to.rel(), MsgInfo::Keyload)
    }

    pub fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Trytes,
        masked_payload: &Trytes,
    ) -> Fallible<Message> {
        self.imp.sign_packet(
            link_to.rel(),
            public_payload,
            masked_payload,
            MsgInfo::SignedPacket,
        )
    }

    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Trytes,
        masked_payload: &Trytes,
    ) -> Fallible<Message> {
        self.imp.tag_packet(
            link_to.rel(),
            public_payload,
            masked_payload,
            MsgInfo::TaggedPacket,
        )
    }

    pub fn unwrap_tagged_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<(Trytes, Trytes)> {
        self.imp
            .handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    pub fn unwrap_subscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<()> {
        self.imp.handle_subscribe(preparsed, MsgInfo::Subscribe)
    }

    pub fn unwrap_unsubscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<()> {
        self.imp.handle_unsubscribe(preparsed, MsgInfo::Unsubscribe)
    }
}
