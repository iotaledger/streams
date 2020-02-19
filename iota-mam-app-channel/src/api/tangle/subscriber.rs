//! Customize Subscriber with default parameters for use over the Tangle.

use failure::Fallible;
use std::str::FromStr;

use super::*;
use crate::api::subscriber::*;
use iota_mam_app::message::*;
use iota_mam_core::{key_encapsulation::ntru, prng, signature::mss, trits::Trits};
use iota_mam_protobuf3::types::Trytes;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberT<Address, Store, LinkGen>,
}

impl Subscriber {
    pub fn new(seed: &str, with_ntru: bool) -> Self {
        let nonce = Trits::from_str("TANGLESUBSCRIBER").unwrap();
        Self {
            imp: SubscriberT::gen(
                Store::default(),
                LinkGen::default(),
                prng::dbg_init_str(seed),
                &nonce,
                with_ntru,
            ),
        }
    }

    /// Ie. has Announce message been handled?
    pub fn is_registered(&self) -> bool {
        self.imp.appinst.is_some()
    }

    /// Just clear inner state except for own keys and link store.
    pub fn unregister(&mut self) {
        self.imp.appinst = None;
        self.imp.author_mss_pk = None;
        self.imp.author_ntru_pk = None;
    }

    pub fn channel_address(&self) -> Option<&AppInst> {
        self.imp
            .appinst
            .as_ref()
            .map(|tangle_address| &tangle_address.appinst)
    }

    pub fn author_mss_public_key(&self) -> &Option<mss::PublicKey> {
        &self.imp.author_mss_pk
    }

    pub fn author_ntru_public_key(&self) -> &Option<ntru::PublicKey> {
        &self.imp.author_ntru_pk
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

    pub fn subscribe(&mut self, link_to: &Address) -> Fallible<Message> {
        //TODO: remove link_to
        self.imp.subscribe(link_to.rel(), MsgInfo::Subscribe)
    }

    pub fn unsubscribe(&mut self, link_to: &Address) -> Fallible<Message> {
        //TODO: lookup link_to Subscribe message.
        self.imp.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    }

    pub fn unwrap_announcement<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<()> {
        self.imp.handle_announcement(preparsed, MsgInfo::Announce)?;
        Ok(())
    }

    pub fn unwrap_change_key<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<()> {
        self.imp.handle_change_key(preparsed, MsgInfo::ChangeKey)?;
        Ok(())
    }

    pub fn unwrap_keyload<'a>(&mut self, preparsed: PreparsedMessage<'a, Address>) -> Fallible<()> {
        self.imp.handle_keyload(preparsed, MsgInfo::Keyload)?;
        Ok(())
    }

    pub fn unwrap_signed_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<(Trytes, Trytes)> {
        self.imp
            .handle_signed_packet(preparsed, MsgInfo::SignedPacket)
    }

    pub fn unwrap_tagged_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, Address>,
    ) -> Fallible<(Trytes, Trytes)> {
        self.imp
            .handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }
}
