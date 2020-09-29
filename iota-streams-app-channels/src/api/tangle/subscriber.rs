//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use core::{
    fmt,
};

use super::*;
use crate::{
    api::{
        user::User,
        tangle::{
            user::SubUser,
            MsgInfo,
        },
    },
};
use iota_streams_app::message::{
    HasLink as _,
    LinkGenerator as _,
};

use iota_streams_core::{
    prelude::Vec,
    prng,
};
use iota_streams_core_edsig::signature::ed25519;
use crate::api::tangle::user::UserImp;

type SubscriberImp = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

/// Subscriber type.
pub struct Subscriber {
    imp: SubscriberImp,
}

impl Subscriber {
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
    ) -> Self {
        let nonce = "TANGLESUBSCRIBERNONCE".as_bytes().to_vec();
        let imp = SubscriberImp::gen(
            prng::dbg_init_str(seed),
            nonce,
            0,
            encoding.as_bytes().to_vec(),
            payload_length,
        );
        Self {
            imp,
        }
    }
}

impl SubUser for Subscriber {
    /// Ie. has Announce message been handled?
    fn is_registered(&self) -> bool {
        self.imp.appinst.is_some()
    }

    /// Just clear inner state except for own keys and link store.
    fn unregister(&mut self) {
        self.imp.appinst = None;
        self.imp.author_sig_pk = None;
    }

    /// Subscribe to a Channel app instance.
    fn subscribe(&mut self, link_to: &Address) -> Result<WrappedMessage> {
        // TODO: remove link_to
        let subscribe = self.imp.subscribe(link_to.rel())?;
        Ok(subscribe)
    }

    /// Handle Channel app instance announcement.
    fn unwrap_announcement<'a>(&mut self, msg: Message) -> Result<()> {
        self.imp.handle_announcement(msg, MsgInfo::Announce)?;
        Ok(())
    }

}

impl UserImp for Subscriber {
    fn get_pk(&self) -> &ed25519::PublicKey {
        &self.imp.sig_kp.public
    }

    /// Return Channel app instance.
    fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|tangle_address| &tangle_address.appinst)
    }

    fn is_multi_branching(&self) -> bool {
        self.imp.is_multi_branching()
    }

    fn commit_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<()> {
        self.imp.commit_message(msg, info)
    }

    /// Create tagged packet.
    fn tag_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(WrappedMessage, Option<WrappedMessage>)> {
        let tagged = self
            .imp
            .tag_packet(link_to.rel(), public_payload, masked_payload)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel())?;
        Ok((tagged, seq))
    }

    /// Create signed packet.
    fn sign_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(WrappedMessage, Option<WrappedMessage>)> {
        let signed = self
            .imp
            .sign_packet(link_to.rel(), public_payload, masked_payload)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel())?;
        Ok((signed, seq))
    }

    // Unsubscribe from the Channel app instance.
    // pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
    // TODO: lookup link_to Subscribe message.
    // self.imp.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    // }


    /// Handle keyload.
    fn unwrap_keyload<'a>(&mut self, msg: Message) -> Result<bool> {
        self.imp.handle_keyload(msg, MsgInfo::Keyload)
    }

    /// Unwrap and verify signed packet.
    fn unwrap_signed_packet<'a>(&mut self, msg: Message) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.imp.handle_signed_packet(msg, MsgInfo::SignedPacket)
    }

    /// Unwrap and verify tagged packet.
    fn unwrap_tagged_packet<'a>(&mut self, msg: Message) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(msg, MsgInfo::TaggedPacket)
    }

    fn unwrap_sequence<'a>(&mut self, msg: Message) -> Result<Address> {
        let seq_link = msg.link.clone();
        let seq_msg = self.imp.handle_sequence(msg, MsgInfo::Sequence)?;
        let msg_id = self
            .imp
            .link_gen
            .link_from((&seq_msg.ref_link, &seq_msg.pk, seq_msg.seq_num.0));

        if self.is_multi_branching() {
            self.store_state(seq_msg.pk, seq_link)
        } else {
            self.store_state_for_all(seq_link, seq_msg.seq_num.0)
        }

        Ok(msg_id)
    }

    fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SequencingState<Address>)> {
        self.imp.gen_next_msg_ids(branching)
    }
    fn store_state(&mut self, pk: ed25519::PublicKey, link: Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.imp.store_state(pk, link.msgid)
    }
    fn store_state_for_all(&mut self, link: Address, seq_num: u64) {
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
