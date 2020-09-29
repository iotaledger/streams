use anyhow::{
    Result,
    ensure,
};

use iota_streams_core::prelude::{
    Vec,
    Rc,
};

use core::cell::RefCell;

use crate::{
    api::{
        Transport,
        tangle::ddml_types::Bytes,
    },
    message,
};
use super::*;

pub trait UserImp {
    fn channel_address(&self) -> Option<&ChannelAddress>;
    fn get_pk(&self) -> &PublicKey;
    fn commit_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<()>;
    fn unwrap_sequence<'a>(&mut self, msg: Message) -> Result<Address>;
    fn is_multi_branching(&self) -> bool;
    fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(PublicKey, SequencingState<Address>)>;
    fn store_state(&mut self, pk: PublicKey, link: Address);
    fn store_state_for_all(&mut self, link: Address, seq_num: u64);
    fn sign_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(WrappedMessage, Option<WrappedMessage>)>;
    fn tag_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(WrappedMessage, Option<WrappedMessage>)>;
    fn unwrap_tagged_packet<'a>(&mut self, msg: Message) -> Result<(Bytes, Bytes)>;
    fn unwrap_signed_packet<'a>(&mut self, msg: Message) -> Result<(ed25519::PublicKey, Bytes, Bytes)>;
    fn unwrap_keyload<'a>(&mut self, msg: Message) -> Result<()>;
}

pub trait AuthUser: UserImp {
    fn announce(&mut self) -> Result<WrappedMessage>;
    fn share_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ke_pks: &Vec<PublicKey>) -> Result<(WrappedMessage, Option<WrappedMessage>)>;
    fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(WrappedMessage, Option<WrappedMessage>)>;
    fn unwrap_subscribe<'a>(&mut self, msg: Message) -> Result<()>;
}

pub trait SubUser: UserImp {
    fn is_registered(&self) -> bool;
    fn unregister(&mut self);
    fn subscribe(&mut self, link_to: &Address) -> Result<WrappedMessage>;
    fn unwrap_announcement<'a>(&mut self, msg: Message) -> Result<()>;
}


pub struct User<Trans, U>
where
    Trans: Transport<DefaultF, Address>,
{
    pub user: U,
    pub transport: Rc<RefCell<Trans>>,
    pub _recv_opt: Trans::RecvOptions,
    pub _send_opt: Trans::SendOptions,
    pub user_type: UserType,
}

impl<Trans, U: UserImp> User<Trans, U>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{
    pub fn channel_address(&mut self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    pub fn is_multi_branching(&mut self) -> bool {
        self.user.is_multi_branching()
    }

    pub fn send_signed_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.sign_packet(link_to, public_payload, masked_payload)?;
        (&*self.transport).borrow_mut().send_message(&msg.0.message)?;
        let msg_link = msg.0.message.link.clone();
        self.user.commit_message(msg.0, MsgInfo::SignedPacket)?;

        let mut seq_link = None;
        if msg.1.is_some() {
            seq_link = self.send_sequence(msg.1.unwrap()).ok();
        }

        Ok((msg_link, seq_link))
    }

    fn send_sequence(&mut self, msg: WrappedMessage) -> Result<Address> {
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let seq_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Sequence)?;
        Ok(seq_link)
    }

    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_sequence(msg)
    }

    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(PublicKey, Bytes, Bytes)> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_signed_packet(msg)
    }

    pub fn send_tagged_packet(&mut self, link_to: &Address, public_payload: &Bytes, masked_payload: &Bytes) -> Result<(Address, Option<Address>)>{
        let msg = self.user.tag_packet(link_to, public_payload, masked_payload)?;
        (&*self.transport).borrow_mut().send_message(&msg.0.message)?;
        let msg_link = msg.0.message.link.clone();
        self.user.commit_message(msg.0, MsgInfo::TaggedPacket)?;

        let mut seq_link = None;
        if msg.1.is_some() {
            seq_link = self.send_sequence(msg.1.unwrap()).ok();
        }

        Ok((msg_link, seq_link))
    }

    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_tagged_packet(msg)
    }

    pub fn handle_message(&mut self, found_msg: Message, pk: Option<PublicKey>) -> Option<(Option<PublicKey>, Address, Bytes, Bytes)> {
        let mut msg = found_msg;
        let base_link = msg.link.clone();

        let mut next_link = base_link.clone();
        let mut unwrapped_content: Option<(Option<PublicKey>, Address, Bytes, Bytes)> = None;

        loop {
            let preparsed = msg.parse_header();
            if preparsed.is_err() {
                break;
            }

            let preparsed = preparsed.unwrap();
            match preparsed.header.content_type {
                message::SIGNED_PACKET => {
                    println!("Signed");
                    let content = self.user.unwrap_signed_packet(msg);
                    if content.is_ok() {
                        let content = content.unwrap();
                        unwrapped_content = Some((Some(content.0), next_link.clone(), content.1, content.2));
                    }
                    break;
                }
                message::TAGGED_PACKET => {
                    let content = self.user.unwrap_tagged_packet(msg);
                    if content.is_ok() {
                        let content = content.unwrap();
                        unwrapped_content = Some((pk, next_link.clone(), content.0, content.1));
                    }
                    break;
                }
                message::KEYLOAD => {
                    let _unwrapped = self.user.unwrap_keyload(msg);
                    unwrapped_content = Some((pk, next_link.clone(), Bytes(Vec::new()), Bytes(Vec::new())));
                    break;
                }
                message::SEQUENCE => {
                    let msg_link = self.user.unwrap_sequence(msg);
                    match msg_link.is_ok() {
                        true => {
                            let msg_link = msg_link.unwrap();
                            let next_msg = (&*self.transport).borrow_mut().recv_message(&msg_link);
                            match next_msg.is_ok() {
                                true => {
                                    msg = next_msg.unwrap();
                                    self.user.store_state(pk.unwrap().clone(), next_link.clone());
                                    next_link = msg_link;
                                }
                                false => { break; }
                            }
                        }
                        false => { break; }
                    }
                }
                _ => {
                    break;
                }
            };
        };

        unwrapped_content
    }

    pub fn fetch_next_msgs(&mut self) -> Vec<(Option<PublicKey>, Address, Bytes, Bytes)> {
        let ids = self.user.gen_next_msg_ids(self.user.is_multi_branching());
        let mut msgs = Vec::new();

        for (pk, SequencingState(link, seq)) in ids {
            let msg = (&*self.transport).borrow_mut().recv_message(&link);

            if msg.is_ok() {
                let msg = self.handle_message(msg.unwrap(), Some(pk));
                if msg.is_some() {
                    if !self.user.is_multi_branching() {
                        self.user.store_state_for_all(link, seq);
                    }

                    msgs.push(msg.unwrap());
                }
            }
        }
        msgs
    }

}


impl<Trans, U: AuthUser + UserImp> User<Trans, U>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{
    pub fn send_announce(&mut self) -> Result<Address> {
        ensure!(self.user_type == UserType::Author, "Only Authors can generate a channel");
        let msg = self.user.announce()?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;

        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Announce)?;
        Ok(msg_link)
    }

    pub fn send_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ke_pks: &Vec<PublicKey>) -> Result<(Address, Option<Address>)> {
        ensure!(self.user_type == UserType::Author, "Only Authors can send Keyload messages");
        let msg = self.user.share_keyload(link_to, psk_ids, ke_pks)?;
        (&*self.transport).borrow_mut().send_message(&msg.0.message)?;
        let msg_link = msg.0.message.link.clone();
        self.user.commit_message(msg.0, MsgInfo::Keyload)?;

        let mut seq_link = None;
        if msg.1.is_some() {
            seq_link = self.send_sequence(msg.1.unwrap()).ok();
        }

        Ok((msg_link, seq_link))
    }

    pub fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        ensure!(self.user_type == UserType::Author, "Only Authors can send Keyload messages");
        let msg = self.user.share_keyload_for_everyone(link_to)?;
        (&*self.transport).borrow_mut().send_message(&msg.0.message)?;
        let msg_link = msg.0.message.link.clone();
        self.user.commit_message(msg.0, MsgInfo::Keyload)?;

        let mut seq_link = None;
        if msg.1.is_some() {
            seq_link = self.send_sequence(msg.1.unwrap()).ok();
        }

        Ok((msg_link, seq_link))
    }

    pub fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        ensure!(self.user_type == UserType::Author, "Only Authors can process a Subscribe message");
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_subscribe(msg)
    }
}

impl<Trans, U: SubUser + UserImp> User<Trans, U>
where
    Trans: Transport<DefaultF, Address>,
    Trans::RecvOptions: Default,
    Trans::SendOptions: Default,
{

    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        ensure!(self.user_type == UserType::Subscriber, "Only Subscribers can receive an announcement");
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_announcement(msg)
    }

    pub fn receive_keyload(&mut self, link: &Address) -> Result<()> {
        ensure!(self.user_type == UserType::Subscriber, "Only Subscribers can receive a Keyload");
        let msg = (&*self.transport).borrow_mut().recv_message(link)?;
        self.user.unwrap_keyload(msg)
    }

    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address>{
        ensure!(self.user_type == UserType::Subscriber, "Only Subscribers can send subscriber messages");
        let msg = self.user.subscribe(link_to)?;
        (&*self.transport).borrow_mut().send_message(&msg.message)?;
        let msg_link = msg.message.link.clone();
        self.user.commit_message(msg, MsgInfo::Subscribe)?;

        Ok(msg_link)
    }

}