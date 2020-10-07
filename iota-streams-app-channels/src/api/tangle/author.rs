//! Customize Author with default implementation for use over the Tangle.

use anyhow::Result;
use core::fmt;

use super::*;
use crate::api::tangle::{
    UnwrappedMessage,
    User,
};

use iota_streams_core::prelude::Vec;
use iota_streams_core_edsig::signature::ed25519;

/// Author type.
pub struct Author<Trans> {
    user: User<Trans>,
}

impl<Trans> Author<Trans>
where
    Trans: Transport,
{
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    pub fn new(seed: &str, encoding: &str, payload_length: usize, multi_branching: bool, transport: Trans) -> Self {
        let mut user = User::new(seed, encoding, payload_length, multi_branching, transport);
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Self { user }
    }

    /// Announce creation of a new Channel.
    pub fn send_announce(&mut self) -> Result<Address> {
        self.user.send_announce()
    }
    /// Create a new keyload for a list of subscribers.
    pub fn send_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload(link_to, psk_ids, ke_pks)
    }

    /// Create keyload for all subscribed subscribers.
    pub fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload_for_everyone(link_to)
    }

    /// Subscribe a new subscriber.
    pub fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        self.user.receive_subscribe(link)
    }

    // Unsubscribe a subscriber
    // pub pub fn receive_unsubscribe(&mut self, link: Address) -> Result<()> {
    // self.user.handle_unsubscribe(link, MsgInfo::Unsubscribe)
    // }

    /// Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    pub fn get_pk(&self) -> &ed25519::PublicKey {
        self.user.get_pk()
    }

    /// Create a signed packet.
    pub fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_signed_packet(link_to, public_payload, masked_payload)
    }

    /// Create a tagged packet.
    pub fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_tagged_packet(link_to, public_payload, masked_payload)
    }

    /// Unwrap tagged packet.
    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link)
    }

    /// Unwrap and verify signed packet.
    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link)
    }

    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link)
    }

    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, Cursor<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: &Address) {
        self.user.store_state(pk, link)
    }

    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u32) {
        self.user.store_state_for_all(link, seq_num)
    }

    pub fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs()
    }

    pub fn receive_msg(&mut self, link: &Address, pk: Option<ed25519::PublicKey>) -> Result<UnwrappedMessage> {
        self.user.receive_message(link, pk)
    }
}

impl<Trans> fmt::Display for Author<Trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.user.user.sig_kp.public.as_bytes()),
            self.user.user.pk_store
        )
    }
}
