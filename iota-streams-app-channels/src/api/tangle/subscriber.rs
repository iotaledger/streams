//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use core::fmt;

use super::*;
use crate::api::user::User;
use iota_streams_app::message::{
    HasLink as _,
    LinkGenerator as _,
};

use iota_streams_core::{
    prelude::Vec,
    prng,
};
use iota_streams_core_edsig::signature::ed25519;

type SubscriberImp = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberImp,
}

impl Subscriber {
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(seed: &str, encoding: &str, payload_length: usize) -> Self {
        let nonce = "TANGLESUBSCRIBERNONCE".as_bytes().to_vec();
        Self {
            imp: SubscriberImp::gen(
                prng::dbg_init_str(seed),
                nonce,
                0,
                encoding.as_bytes().to_vec(),
                payload_length,
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
    }

    /// Return Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|tangle_address| &tangle_address.appinst)
    }

    pub fn is_multi_branching(&self) -> bool {
        self.imp.is_multi_branching()
    }

    // Return Author's Ed25519 public key.
    // pub fn author_sig_public_key(&self) -> &Option<ed25519::PublicKey> {
    // &self.imp.author_sig_pk
    // }
    //
    // Return Author's NTRU public key.
    // pub fn author_ke_public_key(&self) -> &Option<x25519::PublicKeyWrap> {
    // &self.imp.author_ke_pk
    // }
    //
    // pub fn sub_ke_public_key(&self) -> &x25519::PublicKey {
    // &self.imp.ke_kp.1
    // }
    //
    // Sends a sequence message referencing the supplied message if sequencing is enabled.
    // pub fn send_sequence(&mut self, msg_link: &Address) -> Result<Option<Message>> {
    // self.imp.send_sequence(msg_link, MsgInfo::Sequence);
    // }
    //
    // pub fn store_state(&mut self, pubkey: x25519::PublicKey, link: Address) {
    // let seq_num = self.imp.get_seq_state(pubkey).unwrap().1;
    // self.update_state(pubkey, link.clone(), seq_num + 1);
    // }
    //
    // pub fn store_state_for_all(&mut self, link: Address, seq_num: usize) {
    // let pubkey = self.imp.ke_kp.1;
    // let mut pks = self.imp.get_pks();
    // pks.insert(x25519::PublicKeyWrap(pubkey));
    // for pk in pks.iter() {
    // self.update_state(pk.0, link.clone(), seq_num.clone() + 1);
    // }
    // }
    //
    // pub fn update_state(&mut self, pk: x25519::PublicKey, link: Address, seq_num: usize) {
    // self.imp.store_state(pk, link, seq_num);
    // }
    //
    // pub fn get_seq_state(&mut self, pk: x25519::PublicKey) -> Result<(Address, usize)> {
    // self.imp.get_seq_state(pk)
    // }
    //

    /// Create tagged packet.
    pub fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Message, Option<Message>)> {
        let tagged = self
            .imp
            .tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel(), MsgInfo::Sequence)?;
        Ok((tagged, seq))
    }

    /// Subscribe to a Channel app instance.
    pub fn subscribe(&mut self, link_to: &Address) -> Result<Message> {
        // TODO: remove link_to
        let subscribe = self.imp.subscribe(link_to.rel(), MsgInfo::Subscribe)?;
        Ok(subscribe)
    }

    // Unsubscribe from the Channel app instance.
    // pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
    // TODO: lookup link_to Subscribe message.
    // self.imp.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    // }

    /// Handle Channel app instance announcement.
    pub fn unwrap_announcement<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_announcement(preparsed, MsgInfo::Announce)?;
        Ok(())
    }

    /// Handle keyload.
    pub fn unwrap_keyload<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_keyload(preparsed, MsgInfo::Keyload)?;
        Ok(())
    }

    /// Unwrap and verify signed packet.
    pub fn unwrap_signed_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.imp.handle_signed_packet(preparsed, MsgInfo::SignedPacket)
    }

    /// Unwrap and verify tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    pub fn unwrap_sequence<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<Address> {
        let seq_msg = self.imp.handle_sequence(preparsed, MsgInfo::Sequence)?;
        let msg_id = self
            .imp
            .link_gen
            .link_from((&seq_msg.ref_link, &seq_msg.pk, seq_msg.seq_num.0));
        Ok(msg_id)
        // let seq_msg = self.imp.handle_sequence(preparsed, MsgInfo::Sequence)?;
        // let msg_id = self.imp.gen_msg_id(link.rel(), pk, seq)
        // let msg_id = self.gen_msg_id(
        // &Address::new(
        // self.imp.appinst.as_ref().unwrap().appinst.clone(),
        // MsgId::from(seq_msg.ref_link),
        // ),
        // &seq_msg.pubkey,
        // seq_msg.seq_num.0,
        // );
        // Ok(msg_id)
    }

    // pub fn get_branching_flag(&self) -> u8 {
    // self.imp.get_branching_flag()
    // }
    //
    // pub fn gen_msg_id(&mut self, link: &Address, pk: &x25519::PublicKey, seq: usize) -> Address {
    // self.imp.gen_msg_id(link.rel(), pk, seq)
    // }
    //
    // pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(x25519::PublicKey, Address, usize)> {
    // let mut pks = self.imp.get_pks();
    // let mut ids = Vec::new();
    // let self_pk = x25519::PublicKeyWrap(self.imp.ke_kp.1);
    //
    // if !pks.contains(&self_pk) {
    // pks.insert(self_pk);
    // }
    //
    // for pk in pks.iter() {
    // let (seq_link, seq_num) = self.imp.get_seq_state(pk.0).unwrap();
    // if branching {
    // ids.push((pk.0, self.gen_msg_id(&seq_link, &pk.0, 1), 1));
    // } else {
    // In Single Branching instances, while issuing transactions, the sequence state is
    // set to the next message that will be sent, when fetching transactions sent by
    // another publisher, it is necessary to check the current sequence state along with
    // the link rather than the next state. To simplify the search we return both ids
    // ids.push((pk.0, self.gen_msg_id(&seq_link, &pk.0, seq_num), seq_num));
    // ids.push((pk.0, self.gen_msg_id(&seq_link, &pk.0, seq_num - 1), seq_num - 1));
    // }
    // }
    // ids
    // }
    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SequencingState<Address>)> {
        self.imp.gen_next_msg_ids(branching)
    }
    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.imp.store_state(pk, link.msgid)
    }
    pub fn store_state_for_all(&mut self, link: Address, seq_num: u64) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.imp.store_state_for_all(link.msgid, seq_num)
    }
}

impl fmt::Display for Subscriber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.imp.sig_kp.public.as_bytes()),
            self.imp.pk_store
        )
    }
}
