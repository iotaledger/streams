//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use core::{
    fmt,
    cell::RefCell,
};

use super::*;
use crate::{
    api::{
        //user::User,
        tangle::{
            User,
            user::UserInstance,
            MsgInfo,
        },
    },
};

use iota_streams_core::{
    prelude::{Vec, Rc},
    prng,
};
use iota_streams_core_edsig::signature::ed25519;

/// Subscriber type.
pub struct Subscriber<T: Transport> {
    user: User<T>,
}

impl<T: Transport> Subscriber<T>
where
    T::RecvOptions: Copy + Default,
    T::SendOptions: Copy + Default,
{
    /// Create a new Subscriber instance, optionally generate NTRU keypair.
    pub fn new(
        seed: &str,
        encoding: &str,
        payload_length: usize,
        transport: Rc<RefCell<T>>
    ) -> Self {
        let nonce = "TANGLESUBSCRIBERNONCE".as_bytes().to_vec();
        let user = UserInstance::gen(
            prng::dbg_init_str(seed),
            nonce,
            0,
            encoding.as_bytes().to_vec(),
            payload_length,
        );
        Self { user: User { user: user, transport} }
    }

    /// Ie. has Announce message been handled?
    pub fn is_registered(&self) -> bool {
        self.user.is_registered()
    }

    /// Just clear inner state except for own keys and link store.
    pub fn unregister(&mut self) {
        self.user.unregister()
    }

    /// Subscribe to a Channel app instance.
    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address> {
        self.user.send_subscribe(link_to)
    }

    /// Handle Channel app instance announcement.
    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        self.user.receive_announcement(link)
    }

    pub fn get_pk(&self) -> &ed25519::PublicKey {
        self.user.get_pk()
    }

    /// Return Channel app instance.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    pub fn commit_message(&mut self, msg: WrappedMessage, info: MsgInfo) -> Result<Address> {
        self.user.commit_message(msg, info)
    }

    /// Create tagged packet.
    pub fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_tagged_packet(link_to, public_payload, masked_payload)
    }

    /// Create signed packet.
    pub fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_signed_packet(link_to, public_payload, masked_payload)
    }

    // Unsubscribe from the Channel app instance.
    // pub pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
    // TODO: lookup link_to Subscribe message.
    // self.user.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    // }


    /// Handle keyload.
    pub fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        self.user.receive_keyload(link)
    }

    /// Unwrap and verify signed packet.
    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link)

    }

    /// Unwrap and verify tagged packet.
    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link)

    }

    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link)
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SequencingState<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }
    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: &Address) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state(pk, link)
    }
    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u64) {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state_for_all(link, seq_num)
    }

    pub fn fetch_next_msgs(&mut self) -> Vec<(Option<ed25519::PublicKey>, Address, Bytes, Bytes)> {
        self.user.fetch_next_msgs()
    }

}

impl<T: Transport> fmt::Display for Subscriber<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.user.user.sig_kp.public.as_bytes()),
            self.user.user.pk_store
        )
    }
}
