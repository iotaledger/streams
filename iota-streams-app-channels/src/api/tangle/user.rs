use anyhow::{
    anyhow,
    Result,
};

use iota_streams_core::prelude::{
    Vec,
    Rc,
};

use core::cell::RefCell;

use crate::{
    api::{
        user::User as UserImp,
        transport::Transport,
        tangle::{
            ddml_types::Bytes,
            DefaultF,
            MsgInfo,
            MessageReturn,
        },
    },
    message,
};

use iota_streams_app::message::LinkGenerator;
use super::*;

pub type UserInstance = UserImp<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

pub struct User<Trans: Transport<DefaultF, Address>> {
    pub user: UserInstance,
    pub transport: Rc<RefCell<Trans>>,
}

impl<Trans> User<Trans>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.appinst.as_ref().map(|x| &x.appinst)
    }

    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.user.sig_kp.public
    }

    pub fn commit_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<Address> {
        self.user.commit_message(msg, info)
    }

    pub fn store_state(&mut self, pk: PublicKey, link: &Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state(pk, link.msgid.clone())
    }

    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u64) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state_for_all(link.msgid.clone(), seq_num)
    }

    pub fn send_signed_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.sign_packet(&link_to.msgid, public_payload, masked_payload)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::SignedPacket)?;

        let seq_link = self.send_sequence(link_to)?;
        Ok((msg_link, seq_link))
    }

    fn send_sequence(&mut self, ref_link: &Address) -> Result<Option<Address>> {
        let msg = self.user.send_sequence(&ref_link.msgid)?;
        if msg.is_some() {
            let msg = msg.unwrap();
            (&*self.transport).borrow_mut().send_message(&msg.message)?;
            return Ok(Some(self.user.commit_message(msg, MsgInfo::Sequence)?))
        }
        Ok(None)
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(PublicKey, SequencingState<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        if let Some(_addr) = &self.user.appinst {
            let seq_link = msg.link.clone();
            let seq_msg = self.user.handle_sequence(msg, MsgInfo::Sequence)?;
            let msg_id = self
                .user
                .link_gen
                .link_from((&seq_msg.ref_link, &seq_msg.pk, seq_msg.seq_num.0));

            if self.is_multi_branching() {
                self.store_state(seq_msg.pk, &seq_link)
            } else {
                self.store_state_for_all(&seq_link, seq_msg.seq_num.0)
            }

            Ok(msg_id)
        } else {
            Err(anyhow!("No channel registered"))
        }
    }

    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(PublicKey, Bytes, Bytes)> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.handle_signed_packet(msg, MsgInfo::SignedPacket)
    }

    pub fn send_tagged_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.tag_packet(&link_to.msgid, public_payload, masked_payload)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::TaggedPacket)?;

        let seq_link = self.send_sequence(link_to)?;
        Ok((msg_link, seq_link))
    }

    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.handle_tagged_packet(msg, MsgInfo::TaggedPacket)
    }

    pub fn handle_message(&mut self, found_msg: Message, pk: Option<PublicKey>) -> Result<MessageReturn> {
        let mut msg = found_msg;
        let base_link = msg.link.clone();
        let mut next_link = base_link.clone();

        loop {
            let preparsed = msg.parse_header();
            if preparsed.is_err() {
                break;
            }

            let preparsed = preparsed.unwrap();
            match preparsed.header.content_type {
                message::SIGNED_PACKET => {
                    let content = self.user.handle_signed_packet(msg, MsgInfo::SignedPacket)?;
                    return Ok(MessageReturn::new(Some(content.0), next_link.clone(), content.1, content.2))
                }
                message::TAGGED_PACKET => {
                    let content = self.user.handle_tagged_packet(msg, MsgInfo::TaggedPacket)?;
                    return Ok(MessageReturn::new(pk, next_link.clone(), content.0, content.1))
                }
                message::KEYLOAD => {
                    // So long as the unwrap has not failed, we will return a blank object to
                    // inform the user that a message was present, even if the use wasn't part of
                    // the keyload itself. This is to prevent sequencing failures
                    let _content = self.user.handle_keyload(msg, MsgInfo::Keyload)?;
                    return Ok(MessageReturn::new(pk, next_link.clone(), Bytes(Vec::new()), Bytes(Vec::new())))
                }
                message::SEQUENCE => {
                    let unwrapped = self.user.handle_sequence(msg, MsgInfo::Sequence)?;
                    let msg_link = self.user.link_gen.link_from((&unwrapped.ref_link, &unwrapped.pk, unwrapped.seq_num.0));
                    msg = (&*self.transport).borrow_mut().recv_message(&msg_link)?;
                    self.user.store_state(pk.unwrap().clone(), next_link.msgid);
                    next_link = msg_link;
                }
                _ => {
                    return Err(anyhow!("Not a recognised message type..."))
                }
            };
        };

        Err(anyhow!("No message found"))
    }

    pub fn fetch_next_msgs(&mut self) -> Vec<MessageReturn> {
        let ids = self.user.gen_next_msg_ids(self.user.is_multi_branching());
        let mut msgs = Vec::new();

        for (pk, SequencingState(link, seq)) in ids {
            let msg = (&*self.transport).borrow_mut().recv_message(&link);

            if msg.is_ok() {
                let msg = self.handle_message(msg.unwrap(), Some(pk));
                if let Ok(msg) = msg {
                    if !self.user.is_multi_branching() {
                        self.user.store_state_for_all(link.msgid, seq);
                    }

                    msgs.push(msg);
                }
            }
        }
        msgs
    }

/*}


impl<Trans> User<Trans>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{*/
    pub fn send_announce(&mut self) -> Result<Address> {
        let msg = self.user.announce()?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;

        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Announce)?;
        Ok(msg_link)
    }

    pub fn send_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ke_pks: &Vec<PublicKey>) -> Result<(Address, Option<Address>)> {
        let msg = self.user.share_keyload(&link_to.msgid, psk_ids, ke_pks)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Keyload)?;

        let seq_link = self.send_sequence(link_to)?;
        Ok((msg_link, seq_link))
    }

    pub fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        let msg = self.user.share_keyload_for_everyone(&link_to.msgid)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Keyload)?;

        let seq_link = self.send_sequence(link_to)?;
        Ok((msg_link, seq_link))
    }

    pub fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.handle_subscribe(msg, MsgInfo::Subscribe)
    }
/*}

impl<Trans> User<Trans>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{*/

    pub fn is_registered(&self) -> bool {
        self.user.appinst.is_some()
    }

    pub fn unregister(&mut self) {
        self.user.appinst = None;
        self.user.author_sig_pk = None;
    }

    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.handle_announcement(msg, MsgInfo::Announce)
    }

    pub fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.handle_keyload(msg, MsgInfo::Keyload)
    }

    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address>{
        let msg = self.user.subscribe(&link_to.msgid)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Subscribe)?;

        Ok(msg_link)
    }

}