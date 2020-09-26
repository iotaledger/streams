//! Customize Author with default implementation for use over the Tangle.

use anyhow::{
    anyhow,
    Result,
};
use core::{
    fmt,
    cell::RefCell,
};

use super::*;
use crate::{
    api::{
        user::User,
        Transport,
        MsgInfo,
    },
    message,
};
use iota_streams_app::message::{
    HasLink as _,
    LinkGenerator as _,
};

use iota_streams_core::{
    prelude::{Vec, Rc},
    prng,
};
use iota_streams_core_edsig::signature::ed25519;

type AuthorImp<T> = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore, T>;

/// Author type.
pub struct Author<T: Transport<DefaultF, Address>> {
    imp: AuthorImp<T>,
}

impl<T: Transport<DefaultF, Address>> Author<T> {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
        multi_branching: bool,
        transport: Rc<RefCell<T>>,
        recv_opt: <T as transport::Transport<DefaultF, Address>>::RecvOptions,
        send_opt: <T as transport::Transport<DefaultF, Address>>::SendOptions
    ) -> Self {
        let nonce = "TANGLEAUTHORNONCE".as_bytes().to_vec();
        let mut imp = AuthorImp::gen(
            prng::dbg_init_str(seed),
            nonce,
            if multi_branching { 1 } else { 0 },
            encoding.as_bytes().to_vec(),
            payload_length,
            transport,
            recv_opt,
            send_opt
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
    pub fn unwrap_tagged_packet<'a>(&mut self, link: Address) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(link, MsgInfo::TaggedPacket)
    }

    /// Unwrap and verify signed packet.
    pub fn unwrap_signed_packet<'a>(&mut self, link: Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.imp.handle_signed_packet(link, MsgInfo::SignedPacket)
    }

    /// Subscribe a new subscriber.
    pub fn unwrap_subscribe<'a>(&mut self, link: Address) -> Result<()> {
        self.imp.handle_subscribe(link, MsgInfo::Subscribe)
    }

    // Unsubscribe a subscriber
    // pub fn unwrap_unsubscribe<'a>(&mut self, link: Address) -> Result<()> {
    // self.imp.handle_unsubscribe(link, MsgInfo::Unsubscribe)
    // }

    pub fn unwrap_sequence<'a>(&mut self, link: Address) -> Result<Address> {
        if let Some(_addr) = &self.imp.appinst {
            let seq_msg = self.imp.handle_sequence(link, MsgInfo::Sequence)?;
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

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SequencingState<Address>)> {
        self.imp.gen_next_msg_ids(branching)
    }

    pub fn fetch_next_msgs(&mut self) -> Result<Vec<(ed25519::PublicKey, Address, Bytes, Bytes)>> {
        let ids = self.gen_next_msg_ids(self.is_multi_branching());
        let mut msgs = Vec::new();
        let mut exists = false;

        for (pk, SequencingState(link, seq)) in ids {
            let msg = (&*self.imp.transport).borrow_mut().recv_message_with_options(&link, &self.imp.recv_opt);
            if msg.is_ok() {
                let mut msg = msg.unwrap();
                let mut next_link = link.clone();

                loop {
                    let preparsed = msg.parse_header()?;
                    match preparsed.header.content_type.0 {
                        message::SIGNED_PACKET => {
                            let content = self.unwrap_signed_packet(next_link.clone())?;
                            exists = true;
                            msgs.push((content.0, next_link.clone(), content.1, content.2));
                            break;
                        }
                        message::TAGGED_PACKET => {
                            let content = self.unwrap_tagged_packet(next_link.clone())?;
                            exists = true;
                            msgs.push((pk, next_link.clone(), content.0, content.1));
                            break;
                        }
                        message::SEQUENCE => {
                            let msg_link = self.unwrap_sequence(next_link.clone())?;
                            msg = (&*self.imp.transport).borrow_mut().recv_message_with_options(&msg_link, &self.imp.recv_opt)?;
                            self.store_state(pk.clone(), next_link.clone());
                            next_link = msg_link;
                        }
                        _ => {
                            break;
                        }
                    };
                }

                if exists && !self.is_multi_branching() {
                    self.store_state_for_all(link, seq);
                }
            }
        }
        Ok(msgs)
    }

    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.imp.store_state(pk, link.msgid)
    }
    pub fn store_state_for_all(&mut self, link: Address, seq_num: usize) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.imp.store_state_for_all(link.msgid, seq_num)
    }
}

impl<T: Transport<DefaultF, Address>> fmt::Display for Author<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.imp.sig_kp.public.as_bytes()),
            self.imp.pk_store
        )
    }
}
