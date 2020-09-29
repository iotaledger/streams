//! Customize Author with default implementation for use over the Tangle.

use anyhow::{
    anyhow,
    Result,
    bail,
};
use core::{
    fmt,
};

use super::*;
use crate::{
    api::{
        user::User,
        tangle::{
            user::{AuthUser, UserImp},
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

type AuthorImp = User<DefaultF, Address, LinkGen, LinkStore, PkStore, PskStore>;

/// Author type.
pub struct Author {
    imp: AuthorImp,
}

impl Author {
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
        multi_branching: bool,
    ) -> Self {
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
}

impl AuthUser for Author {
    /// Announce creation of a new Channel.
    fn announce(&mut self) -> Result<WrappedMessage> {
        self.imp.announce()
    }
    /// Create a new keyload for a list of subscribers.
    fn share_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<(WrappedMessage, Option<WrappedMessage>)> {
        let keyload = self
            .imp
            .share_keyload(link_to.rel(), psk_ids, ke_pks)
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel())?;
        Ok((keyload, seq))
    }

    /// Create keyload for all subscribed subscribers.
    fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(WrappedMessage, Option<WrappedMessage>)> {
        let keyload = self
            .imp
            .share_keyload_for_everyone(link_to.rel())
            .unwrap();
        let seq = self.imp.send_sequence(link_to.rel())?;
        Ok((keyload, seq))
    }

    /// Subscribe a new subscriber.
     fn unwrap_subscribe<'a>(&mut self, msg: Message) -> Result<()> {
        self.imp.handle_subscribe(msg, MsgInfo::Subscribe)
    }

    // Unsubscribe a subscriber
    // pub fn unwrap_unsubscribe<'a>(&mut self, link: Address) -> Result<()> {
    // self.imp.handle_unsubscribe(link, MsgInfo::Unsubscribe)
    // }
}

impl UserImp for Author {
    /// Channel app instance.
    fn channel_address(&self) -> Option<&ChannelAddress> {
        self.imp.appinst.as_ref().map(|x| &x.appinst)
    }

    fn get_pk(&self) -> &ed25519::PublicKey {
        &self.imp.sig_kp.public
    }

    fn commit_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<()> {
        self.imp.commit_message(msg, info)
    }

    /// Create a signed packet.
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

    /// Create a tagged packet.
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

    /// Unwrap tagged packet.
    fn unwrap_tagged_packet<'a>(&mut self, msg: Message) -> Result<(Bytes, Bytes)> {
        self.imp.handle_tagged_packet(msg, MsgInfo::TaggedPacket)
    }

    /// Unwrap and verify signed packet.
    fn unwrap_signed_packet<'a>(&mut self, msg: Message) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.imp.handle_signed_packet(msg, MsgInfo::SignedPacket)
    }

    fn unwrap_sequence<'a>(&mut self, msg: Message) -> Result<Address> {
        if let Some(_addr) = &self.imp.appinst {
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
        } else {
            Err(anyhow!("No channel registered"))
        }
    }

    fn unwrap_keyload(&mut self, _msg: Message) -> Result<bool> {
        bail!("Author cannot unwrap keyload message");
    }

    fn is_multi_branching(&self) -> bool {
        self.imp.is_multi_branching()
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

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.imp.sig_kp.public.as_bytes()),
            self.imp.pk_store
        )
    }
}
