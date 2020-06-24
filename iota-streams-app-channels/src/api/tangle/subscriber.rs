//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use std::str::FromStr;

use super::*;
use crate::api::subscriber::SubscriberT;
use iota_streams_app::message::HasLink as _;

use iota_streams_core::{
    prng,
    tbits::Tbits,
};

type SubscriberImp = SubscriberT<DefaultTW, DefaultF, DefaultP, Address, Store, LinkGen>;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberImp,
}

impl Subscriber {
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(seed: &str, with_ntru: bool) -> Self {
        let nonce = Tbits::from_str("TANGLESUBSCRIBER").unwrap();
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

    /// Return Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|tangle_address| &tangle_address.appinst)
    }

    /// Return Author's MSS public key.
    pub fn author_mss_public_key(&self) -> &Option<MssPublicKey> {
        &self.imp.author_mss_pk
    }

    /// Return Author's NTRU public key.
    pub fn author_ntru_public_key(&self) -> &Option<NtruPublicKey> {
        &self.imp.author_ntru_pk
    }

    /// Create tagged packet.
    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Trytes,
        masked_payload: &Trytes,
    ) -> Result<Message> {
        self.imp
            .tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket)
    }

    /// Subscribe to a Channel app instance.
    pub fn subscribe(&mut self, link_to: &Address) -> Result<Message> {
        //TODO: remove link_to
        self.imp.subscribe(link_to.rel(), MsgInfo::Subscribe)
    }

    /// Unsubscribe from the Channel app instance.
    pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
        //TODO: lookup link_to Subscribe message.
        self.imp.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    }

    /// Handle Channel app instance announcement.
    pub fn unwrap_announcement<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_announcement(preparsed, MsgInfo::Announce)?;
        self.imp
            .link_gen
            .reset_appinst(self.imp.appinst.as_ref().unwrap().base().clone());
        Ok(())
    }

    /// Handle key change.
    pub fn unwrap_change_key<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_change_key(preparsed, MsgInfo::ChangeKey)?;
        Ok(())
    }

    /// Handle keyload.
    pub fn unwrap_keyload<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_keyload(preparsed, MsgInfo::Keyload)?;
        Ok(())
    }

    /// Unwrap and verify signed packet.
    pub fn unwrap_signed_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Trytes, Trytes)> {
        self.imp.handle_signed_packet(preparsed, MsgInfo::SignedPacket)
    }

    /// Unwrap and verify tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Trytes, Trytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }
}
