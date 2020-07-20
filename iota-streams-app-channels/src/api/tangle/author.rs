//! Customize Author with default implementation for use over the Tangle.

use anyhow::Result;

use super::*;
use crate::api::author::AuthorT;
use iota_streams_app::message::HasLink as _;

use iota_streams_core::prng;
use iota_streams_core_edsig::key_exchange::x25519;

type AuthorImp = AuthorT<DefaultF, Address, Store, LinkGen>;

/// Author type.
pub struct Author {
    imp: AuthorImp,
}

impl Author {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(seed: &str, multi_branching: bool) -> Self {
        let nonce = "TANGLEAUTHORNONCE".as_bytes().to_vec();
        Self {
            imp: AuthorT::gen(
                Store::default(),
                LinkGen::default(),
                prng::dbg_init_str(seed),
                nonce,
                multi_branching
            ),
        }
    }

    /// Channel app instance.
    pub fn channel_address(&self) -> &ChannelAddress {
        &self.imp.appinst.appinst
    }

    pub fn get_pk(&self) -> &x25519::PublicKey { &self.imp.ke_kp.1 }

    /// Announce creation of a new Channel.
    pub fn announce(&mut self) -> Result<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    /// Create a new keyload for a list of subscribers.
    pub fn share_keyload(&mut self, link_to: &Address,
                         psk_ids: &PskIds,
                         ke_pks: &Vec<x25519::PublicKeyWrap>
    ) -> Result<(Message, Option<Message>)> {
        let keyload = self.imp
            .share_keyload(link_to.rel(), psk_ids, ke_pks, MsgInfo::Keyload).unwrap();
        let sequenced = self.send_sequence(&link_to);
        Ok((keyload, sequenced))
    }

    /// Create keyload for all subscribed subscribers.
    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Message, Option<Message>)> {
        let keyload = self.imp.share_keyload_for_everyone(link_to.rel(), MsgInfo::Keyload).unwrap();
        let sequenced = self.send_sequence(&link_to);
        Ok((keyload, sequenced))
    }

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

    /// Create a signed packet.
    pub fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Message, Option<Message>)> {
        let signed = self.imp
            .sign_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::SignedPacket).unwrap();
        let sequenced = self.send_sequence(&link_to);
        Ok((signed, sequenced))
    }

    /// Create a tagged packet.
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

    pub fn unwrap_sequence<'a>(&mut self, preparsed: Preparsed<'a>) -> Result<Address> {
        let seq_msg = self.imp.handle_sequence(preparsed, MsgInfo::Sequence).unwrap();
        let msg_id = self.gen_msg_id(
            &Address::new(self.imp.appinst.appinst.clone(), MsgId::from(seq_msg.ref_link)),
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

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(x25519::PublicKey, Address, usize)> {
        let mut pks = self.imp.get_pks();
        let mut ids =Vec::new();
        let self_pk = x25519::PublicKeyWrap(self.imp.ke_kp.1);

        if !pks.contains(&self_pk) {
            pks.insert(self_pk);
        }

        for pk in pks.iter() {
            let (seq_link, seq_num) = self.imp.get_seq_state(pk.0).unwrap();
            if branching {
                ids.push((pk.0, self.gen_msg_id(&seq_link, pk.0, 1), 1));
            } else {
                // In Single Branching instances, while issuing transactions, the sequence state is
                // set to the next message that will be sent, when fetching transactions sent by
                // another publisher, it is necessary to check the current sequence state along with
                // the link rather than the next state. To simplify the search we return both ids
                ids.push((pk.0, self.gen_msg_id(&seq_link, pk.0, seq_num), seq_num));
                ids.push((pk.0, self.gen_msg_id(&seq_link, pk.0, seq_num - 1), seq_num - 1));
            }
        }
        ids
    }
}
