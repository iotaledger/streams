use anyhow::{
    anyhow,
    Result,
};

use iota_streams_core::{
    prelude::Vec,
    prng,
};
use iota_streams_app::{
    message::{LinkGenerator, HasLink as _, },
};

use super::*;
use crate::{
    api,
    message,
};


type UserImp = api::user::User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

pub struct User<Trans> {
    pub user: UserImp,
    pub transport: Trans,
}

#[cfg(not(feature = "async"))]
impl<Trans> User<Trans>
where
    Trans: Transport,
{
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
        multi_branching: bool,
        transport: Trans,
    ) -> Self {
        let nonce = "TANGLEUSERNONCE".as_bytes().to_vec();
        let user = UserImp::gen(
            prng::dbg_init_str(seed),
            nonce,
            if multi_branching { 1 } else { 0 },
            encoding.as_bytes().to_vec(),
            payload_length,
        );
        Self { user, transport, }
    }

    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.appinst.as_ref().map(|x| &x.appinst)
    }

    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.user.sig_kp.public
    }

    pub fn store_state(&mut self, pk: PublicKey, link: &Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state(pk, link.msgid.clone())
    }

    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u32) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state_for_all(link.msgid.clone(), seq_num)
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(PublicKey, Cursor<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    fn send_sequence(&mut self, wrapped: WrappedSequence) -> Result<Option<Address>> {
        if let Some(seq_msg) = wrapped.0 {
            self.transport.send_message(&Message::new(seq_msg))?;
        }

        if let Some(wrap_state) = wrapped.1 {
            self.user.commit_sequence(wrap_state, MsgInfo::Sequence)
        } else {
            Ok(None)
        }
    }

    fn send_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<Address> {
        self.transport.send_message(&Message::new(msg.message))?;
        self.user.commit_wrapped(msg.wrapped, info)
    }

    fn send_message_sequenced(&mut self, msg: WrappedMessage, ref_link: &MsgId, info: MsgInfo) -> Result<(Address, Option<Address>)> {
        let seq = self.user.wrap_sequence(ref_link)?;
        self.transport.send_message(&Message::new(msg.message))?;
        let seq_link = self.send_sequence(seq)?;
        let msg_link = self.user.commit_wrapped(msg.wrapped, info)?;
        Ok((msg_link, seq_link))
    }

    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        let msg = self.transport.recv_message(link)?;
        if let Some(_addr) = &self.user.appinst {
            let seq_link = msg.binary.link.clone();
            let seq_msg = self.user.handle_sequence(msg.binary, MsgInfo::Sequence)?.body;
            let msg_id = self
                .user
                .link_gen
                .link_from(
                    &seq_msg.pk,
                    Cursor::new_at(
                        &seq_msg.ref_link,
                        0,
                        seq_msg.seq_num.0 as u32,
                    )
                );

            if self.is_multi_branching() {
                self.store_state(seq_msg.pk, &seq_link)
            } else {
                self.store_state_for_all(&seq_link, seq_msg.seq_num.0 as u32)
            }

            Ok(msg_id)
        } else {
            Err(anyhow!("No channel registered"))
        }
    }


    pub fn send_signed_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.sign_packet(&link_to.msgid, public_payload, masked_payload)?;
        self.send_message_sequenced(msg, link_to.rel(), MsgInfo::SignedPacket)
    }

    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(PublicKey, Bytes, Bytes)> {
        let msg = self.transport.recv_message(link)?;
        //TODO: msg.timestamp is lost
        let m = self.user.handle_signed_packet(msg.binary, MsgInfo::SignedPacket)?;
        Ok(m.body)
    }

    pub fn send_tagged_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.tag_packet(&link_to.msgid, public_payload, masked_payload)?;
        self.send_message_sequenced(msg, link_to.rel(), MsgInfo::TaggedPacket)
    }

    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        let msg = self.transport.recv_message(link)?;
        let m = self.user.handle_tagged_packet(msg.binary, MsgInfo::TaggedPacket)?;
        Ok(m.body)
    }

    pub fn handle_message(&mut self, msg: Message, pk: Option<PublicKey>) -> Result<UnwrappedMessage> {
        // Forget TangleMessage and timestamp
        let msg = msg.binary;
        let preparsed = msg.parse_header()?;
        match preparsed.header.content_type {
            message::SIGNED_PACKET => {
                let m = self.user.handle_signed_packet(msg, MsgInfo::SignedPacket)?;
                let u = m.map(
                    |(pk, public, masked)|
                    MessageContent::new_signed_packet(pk, public, masked)
                );
                Ok(u)
            }
            message::TAGGED_PACKET => {
                let m = self.user.handle_tagged_packet(msg, MsgInfo::TaggedPacket)?;
                let u = m.map(
                    |(public, masked)|
                    MessageContent::new_tagged_packet(public, masked)
                );
                Ok(u)
            }
            message::KEYLOAD => {
                // So long as the unwrap has not failed, we will return a blank object to
                // inform the user that a message was present, even if the use wasn't part of
                // the keyload itself. This is to prevent sequencing failures
                let m = self.user.handle_keyload(msg, MsgInfo::Keyload)?;
                // TODO: Verify content, whether user is allowed or not!
                let u = m.map(
                    |_allowed|
                    MessageContent::new_keyload()
                );
                Ok(u)
            }
            message::SEQUENCE => {
                let store_link = msg.link.rel().clone();
                let unwrapped = self.user.handle_sequence(msg, MsgInfo::Sequence)?;
                let msg_link = self.user.link_gen.link_from(
                    &unwrapped.body.pk,
                    Cursor::new_at(
                        &unwrapped.body.ref_link,
                        0,
                        unwrapped.body.seq_num.0 as u32,
                    )
                );
                let msg = self.transport.recv_message(&msg_link)?;
                self.user.store_state(pk.unwrap().clone(), store_link);
                self.handle_message(msg, pk)
            }
            unknown_content => {
                Err(anyhow!("Not a recognised message type: {}", unknown_content))
            }
        }
    }

    pub fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        let ids = self.user.gen_next_msg_ids(self.user.is_multi_branching());
        let mut msgs = Vec::new();

        for (pk, Cursor{ link, branch_no: _, seq_no, }) in ids {
            let msg = self.transport.recv_message(&link);

            if msg.is_ok() {
                let msg = self.handle_message(msg.unwrap(), Some(pk));
                if let Ok(msg) = msg {
                    if !self.user.is_multi_branching() {
                        self.user.store_state_for_all(link.msgid, seq_no);
                    }

                    msgs.push(msg);
                }
            }
        }
        msgs
    }


    pub fn send_announce(&mut self) -> Result<Address> {
        let msg = self.user.announce()?;
        self.send_message(msg, MsgInfo::Announce)
    }

    pub fn send_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ke_pks: &Vec<PublicKey>) -> Result<(Address, Option<Address>)> {
        let msg = self.user.share_keyload(&link_to.msgid, psk_ids, ke_pks)?;
        self.send_message_sequenced(msg, link_to.rel(), MsgInfo::Keyload)
    }

    pub fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        let msg = self.user.share_keyload_for_everyone(&link_to.msgid)?;
        self.send_message_sequenced(msg, link_to.rel(), MsgInfo::Keyload)
    }

    pub fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        let msg = self.transport.recv_message(link)?;
        //TODO: Timestamp is lost.
        self.user.handle_subscribe(msg.binary, MsgInfo::Subscribe)
    }


    pub fn is_registered(&self) -> bool {
        self.user.appinst.is_some()
    }

    pub fn unregister(&mut self) {
        self.user.appinst = None;
        self.user.author_sig_pk = None;
    }

    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        let msg = self.transport.recv_message(link)?;
        self.user.handle_announcement(msg.binary, MsgInfo::Announce)
    }

    pub fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        let msg = self.transport.recv_message(link)?;
        let m = self.user.handle_keyload(msg.binary, MsgInfo::Keyload)?;
        Ok(m.body)
    }

    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address>{
        let msg = self.user.subscribe(&link_to.msgid)?;
        self.send_message(msg, MsgInfo::Subscribe)
    }

    pub fn receive_message(&mut self, link: &Address, pk: Option<PublicKey>) -> Result<UnwrappedMessage> {
        let msg = self.transport.recv_message(link)?;
        self.handle_message(msg, pk)
    }
}
