//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use std::str::FromStr;

use super::*;
use crate::api::subscriber::SubscriberT;
use iota_streams_app::message::HasLink as _;

use iota_streams_core::{
    prng,
};

type SubscriberImp = SubscriberT<DefaultF, Address, Store, LinkGen>;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberImp,
}

impl Subscriber {
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(seed: &str) -> Self {
        let nonce = "TANGLESUBSCRIBERNONCE".as_bytes().to_vec();
        Self {
            imp: SubscriberT::gen(
                Store::default(),
                LinkGen::default(),
                prng::dbg_init_str(seed),
                nonce,
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
        self.imp.author_sig_pk = None;
        self.imp.author_ke_pk = None;
    }

    /// Return Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|tangle_address| &tangle_address.appinst)
    }

    /// Return Author's Ed25519 public key.
    pub fn author_sig_public_key(&self) -> &Option<ed25519::PublicKey> {
        &self.imp.author_sig_pk
    }

    /// Return Author's NTRU public key.
    pub fn author_ke_public_key(&self) -> &Option<x25519::PublicKeyWrap> {
        &self.imp.author_ke_pk
    }

    pub fn sub_ke_public_key(&self) -> &x25519::PublicKey { &self.imp.ke_kp.1 }

    /// Create tagged packet.
    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Message, Option<Message>)> {
        let tagged = self.imp
            .tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket).unwrap();
        let sequenced = self.send_sequence(&link_to);
        Ok((tagged, sequenced))
    }

    /// Subscribe to a Channel app instance.
    pub fn subscribe(&mut self, link_to: &Address) -> Result<Message> {
        //TODO: remove link_to
        let subscribe = self.imp.subscribe(link_to.rel(), MsgInfo::Subscribe).unwrap();
        Ok(subscribe)
    }

    /*
    /// Unsubscribe from the Channel app instance.
    pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
        //TODO: lookup link_to Subscribe message.
        self.imp.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    }
     */

    /// Sends a sequence message referencing the supplied message if sequencing is enabled.
    pub fn send_sequence(&mut self, msg_link: &Address) -> Option<Message> {
        let sequenced: Option<Message>;
        let (seq_link, seq_num) = self.imp.get_seq_state(self.imp.ke_kp.1).unwrap();

        if self.imp.get_branching_flag() == &1_u8 {
            let msg = self.imp.sequence(msg_link.rel().tbits().clone(), seq_link.rel().clone(), seq_num, MsgInfo::Sequence).unwrap();
            self.store_state(self.imp.ke_kp.1, msg.link.clone());
            sequenced = Some(msg);
        } else {
            self.store_state_for_all(msg_link.clone(), seq_num);
            sequenced = None;
        }
        sequenced
    }

    pub fn store_state(&mut self, pubkey: x25519::PublicKey, link: Address) {
        let seq_num = self.imp.get_seq_state(pubkey).unwrap().1;
        self.update_state(pubkey, link.clone(), seq_num + 1);
    }

    pub fn store_state_for_all(&mut self, link: Address, seq_num: usize) {
        let pubkey = self.imp.ke_kp.1;
        let mut pks = self.imp.get_pks();
        pks.insert(x25519::PublicKeyWrap(pubkey));
        for pk in pks.iter() {
            self.update_state(pk.0, link.clone(), seq_num.clone() + 1);
        }
    }

    pub fn update_state(&mut self, pk: x25519::PublicKey, link: Address, seq_num: usize) {
        self.imp.store_state(pk, link, seq_num);
    }

    pub fn get_seq_state(&mut self, pk: x25519::PublicKey) -> Result<(Address, usize)> {
        self.imp.get_seq_state(pk)
    }

    /// Handle Channel app instance announcement.
    pub fn unwrap_announcement<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        let msg_link = preparsed.header.link.clone();
        self.imp.handle_announcement(preparsed, MsgInfo::Announce)?;
        self.imp
            .link_gen
            .reset_appinst(self.imp.appinst.as_ref().unwrap().base().clone());
        let pubkey = self.imp.ke_kp.1;
        self.update_state(self.imp.author_ke_pk.clone().unwrap().0, msg_link.clone(), 2);
        self.update_state(pubkey, msg_link, 2);
        Ok(())
    }

    /// Handle keyload.
    pub fn unwrap_keyload<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_keyload(preparsed, MsgInfo::Keyload)?;
        Ok(())
    }

    /// Unwrap and verify signed packet.
    pub fn unwrap_signed_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Bytes, Bytes)> {
        self.imp.handle_signed_packet(preparsed, MsgInfo::SignedPacket)
    }

    /// Unwrap and verify tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    pub fn unwrap_sequence<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<Address> {
        let seq_msg = self.imp.handle_sequence(preparsed, MsgInfo::Sequence).unwrap();
        let msg_id = self.gen_msg_id(
            &Address::new(self.imp.appinst.as_ref().unwrap().appinst.clone(), MsgId::from(seq_msg.ref_link)),
            seq_msg.pubkey,
            seq_msg.seq_num.0,
        );
        Ok(msg_id)
    }

    pub fn get_branching_flag<'a>(&self) -> &u8 {
        self.imp.get_branching_flag()
    }

    pub fn gen_msg_id(&mut self, link: &Address, pk: x25519::PublicKey, seq: usize) -> Address {
        self.imp.gen_msg_id(link.rel(), pk, seq)
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool, retry: bool) -> Vec<(x25519::PublicKey, Address, usize)> {
        let mut pks = self.imp.get_pks();
        let mut ids =Vec::new();
        let self_pk = x25519::PublicKeyWrap(self.imp.ke_kp.1);

        if !pks.contains(&self_pk) {
            pks.insert(self_pk);
        }

        let mut seq_num: usize;
        for pk in pks.iter() {
            let (seq_link, seq_state_num) = self.imp.get_seq_state(pk.0).unwrap();
            seq_num = seq_state_num;
            if branching {
                seq_num = 1;
            } else if retry && seq_num > 2 {
                seq_num -= 1
            }
            let id = self.gen_msg_id(&seq_link, pk.0, seq_num.clone());
            ids.push((pk.0, id, seq_num));
        }
        ids
    }
}
