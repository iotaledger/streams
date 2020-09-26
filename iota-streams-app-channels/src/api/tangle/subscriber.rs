//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use core::{
    fmt,
    cell::RefCell,
};

use super::*;
use crate::{
    api::{
        user::User,
        Transport,
        tangle::ddml_types::Bytes as ByteObject,
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

type SubscriberImp<T> = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore, T>;

/// Subscriber type.
pub struct Subscriber<T:  Transport<DefaultF, Address>> {
    imp: SubscriberImp<T>,
}

impl<T: Transport<DefaultF, Address>> Subscriber<T> {
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
        transport: Rc<RefCell<T>>,
        recv_opt: <T as transport::Transport<DefaultF, Address>>::RecvOptions,
        send_opt: <T as transport::Transport<DefaultF, Address>>::SendOptions,
    ) -> Self {
        let nonce = "TANGLESUBSCRIBERNONCE".as_bytes().to_vec();
        Self {
            imp: SubscriberImp::gen(
                prng::dbg_init_str(seed),
                nonce,
                0,
                encoding.as_bytes().to_vec(),
                payload_length,
                transport,
                recv_opt,
                send_opt
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

    pub fn get_pk(&self) -> &ed25519::PublicKey {
        &self.imp.sig_kp.public
    }

    /// Return Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|tangle_address| &tangle_address.appinst)
    }

    pub fn is_multi_branching(&self) -> bool {
        self.imp.is_multi_branching()
    }

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
    pub fn unwrap_announcement<'a>(&mut self, link: Address) -> Result<()> {
        self.imp.handle_announcement(link, MsgInfo::Announce)?;
        Ok(())
    }

    /// Handle keyload.
    pub fn unwrap_keyload<'a>(&mut self, link: Address) -> Result<()> {
        self.imp.handle_keyload(link, MsgInfo::Keyload)?;
        Ok(())
    }

    /// Unwrap and verify signed packet.
    pub fn unwrap_signed_packet<'a>(&mut self, link: Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.imp.handle_signed_packet(link, MsgInfo::SignedPacket)
    }

    /// Unwrap and verify tagged packet.
    pub fn unwrap_tagged_packet<'a>(&mut self, link: Address) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(link, MsgInfo::TaggedPacket)
    }

    pub fn unwrap_sequence<'a>(&mut self, link: Address) -> Result<Address> {
        let seq_msg = self.imp.handle_sequence(link, MsgInfo::Sequence)?;
        let msg_id = self
            .imp
            .link_gen
            .link_from((&seq_msg.ref_link, &seq_msg.pk, seq_msg.seq_num.0));
        Ok(msg_id)
    }

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
                    match preparsed.header.content_type {
                        message::SIGNED_PACKET => {
                            let content = self.unwrap_signed_packet(next_link.clone());
                            exists = true;
                            if content.is_ok() {
                                let content = content.unwrap();
                                msgs.push((content.0, next_link.clone(), content.1, content.2));
                            }
                            break;
                        }
                        message::TAGGED_PACKET => {
                            let content = self.unwrap_tagged_packet(next_link.clone());
                            exists = true;
                            if content.is_ok() {
                                let content = content.unwrap();
                                msgs.push((pk, next_link.clone(), content.0, content.1));
                            }
                            break;
                        }
                        message::KEYLOAD => {
                            assert!(pk.eq(&self.imp.author_sig_pk.unwrap()), "Cannot process keyload, it was not sent by author");
                            let _unwrapped = self.unwrap_keyload(next_link.clone());
                            exists = true;
                            msgs.push((pk, next_link.clone(), ByteObject(Vec::new()), ByteObject(Vec::new())));
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

}

impl<T: Transport<DefaultF, Address>> fmt::Display for Subscriber<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.imp.sig_kp.public.as_bytes()),
            self.imp.pk_store
        )
    }
}
