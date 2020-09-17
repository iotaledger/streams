//! Customize Author with default implementation for use over the Tangle.

use anyhow::{
    anyhow,
    Result,
};
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

type AuthorImp = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

/// Author type.
pub struct Author {
    imp: AuthorImp,
}

impl Author {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(seed: &str, encoding: &str, payload_length: usize, multi_branching: bool) -> Self {
        let nonce = "TANGLEAUTHORNONCE".as_bytes().to_vec();
        let mut imp = AuthorImp::gen(
            prng::dbg_init_str(seed),
            nonce,
            if multi_branching { 1 } else { 0 },
            encoding.as_bytes().to_vec(),
            payload_length,
        );
        let channel_idx = 0_u64;
        let _ = imp.create_channel(channel_idx);
        Self { imp }
    }

    /// Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|x| &x.appinst)
    }

    pub fn get_pk(&self) -> &ed25519::PublicKey {
        &self.imp.sig_kp.public
    }

    /// Announce creation of a new Channel.
    pub fn announce(&mut self) -> Result<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    /// Create a new keyload for a list of subscribers.
    pub fn share_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<(Message, Option<Message>)> {
        let keyload = self
            .imp
            .share_keyload(link_to.rel(), psk_ids, ke_pks, MsgInfo::Keyload)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel(), MsgInfo::Sequence)?;
        Ok((keyload, seq))
    }

    /// Create keyload for all subscribed subscribers.
    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Message, Option<Message>)> {
        let keyload = self
            .imp
            .share_keyload_for_everyone(link_to.rel(), MsgInfo::Keyload)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel(), MsgInfo::Sequence)?;
        Ok((keyload, seq))
    }

    // Sends a sequence message referencing the supplied message if sequencing is enabled.
    // pub fn send_sequence(&mut self, msg_link: &Address) -> Result<Option<Message>> {
    // self.imp.send_sequence(msg_link, MsgInfo::Sequence)
    // }
    //
    // pub fn update_state(&mut self, pubkey: x25519::PublicKey, link: Address) {
    // self.imp.update_state(pubkey, link)
    // }
    //
    // pub fn update_state_for_all(&mut self, link: Address, seq_num: usize) {
    // self.imp.update_state_for_all(link, seq_num)
    // }
    //
    // pub fn store_state(&mut self, pk: x25519::PublicKey, link: Address, seq_num: usize) {
    // self.imp.store_state(pk, link, seq_num);
    // }
    //
    // pub fn get_seq_state(&mut self, pk: &x25519::PublicKey) -> Option<&(Address, usize)> {
    // self.imp.get_seq_state(pk)
    // }

    /// Create a signed packet.
    pub fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Message, Option<Message>)> {
        let signed = self
            .imp
            .sign_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::SignedPacket)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel(), MsgInfo::Sequence)?;
        Ok((signed, seq))
    }

    /// Create a tagged packet.
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

    /// Unwrap tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(preparsed, MsgInfo::TaggedPacket)
    }

    /// Subscribe a new subscriber.
    pub fn unwrap_subscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
        self.imp.handle_subscribe(preparsed, MsgInfo::Subscribe)
    }

    // Unsubscribe a subscriber
    // pub fn unwrap_unsubscribe<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<()> {
    // self.imp.handle_unsubscribe(preparsed, MsgInfo::Unsubscribe)
    // }

    pub fn unwrap_sequence<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<Address> {
        if let Some(_addr) = &self.imp.appinst {
            let seq_msg = self.imp.handle_sequence(preparsed, MsgInfo::Sequence)?;
            let msg_id = self
                .imp
                .link_gen
                .link_from((&seq_msg.ref_link, &seq_msg.pk, seq_msg.seq_num.0));
            Ok(msg_id)
        } else {
            Err(anyhow!("No channel registered"))
        }
    }

    pub fn is_multi_branching(&self) -> bool {
        self.imp.is_multi_branching()
    }

    // pub fn gen_msg_id(&mut self, link: &Address, pk: &x25519::PublicKey, seq: usize) -> Address {
    // self.imp.gen_msg_id(link.rel(), pk, seq)
    // }
    //
    // pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(x25519::PublicKey, Address, usize)> {
    // let pks = self.imp.get_pks();
    // let mut ids = Vec::new();
    // let self_pk = x25519::PublicKeyWrap(self.imp.ke_kp.1);
    //
    // if !pks.contains(&self_pk) {
    // pks.insert(self_pk);
    // }
    //
    // for pk in pks.iter() {
    // let (seq_link, seq_num) = self.imp.get_seq_state(&pk.0).unwrap();
    // if branching {
    // ids.push((pk.0, self.gen_msg_id(&seq_link, &pk.0, 1), 1));
    // } else {
    // In Single Branching instances, while issuing transactions, the sequence state is
    // set to the next message that will be sent, when fetching transactions sent by
    // another publisher, it is necessary to check the current sequence state along with
    // the link rather than the next state. To simplify the search we return both ids
    // let seq_num = *seq_num;
    // let seq_num1 = seq_num - 1;
    // let msgid = self.imp.gen_msg_id(seq_link.rel(), &pk.0, seq_num);
    // let msgid1 = self.imp.gen_msg_id(seq_link.rel(), &pk.0, seq_num1);
    // ids.push((pk.0, msgid, seq_num));
    // ids.push((pk.0, msgid1, seq_num1));
    // }
    // }
    // ids
    // }
    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SeqState)> {
        self.imp.gen_next_msg_ids(branching)
    }
    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: Address) {
        self.imp.store_state(pk, link)
    }
    pub fn store_state_for_all(&mut self, link: Address, seq_num: usize) {
        self.imp.store_state_for_all(link, seq_num)
    }
}

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>\n{}", hex::encode(self.imp.sig_kp.public.as_bytes()), self.imp.pk_store)
    }
}
