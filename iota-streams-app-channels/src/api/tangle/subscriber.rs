//! Customize Subscriber with default parameters for use over the Tangle.

use anyhow::Result;
use core::fmt;

use super::*;
use crate::api::tangle::{
    UnwrappedMessage,
    User,
};

use iota_streams_core::prelude::Vec;
use iota_streams_core_edsig::signature::ed25519;

/// Subscriber Object. Contains User API.
pub struct Subscriber<T> {
    user: User<T>,
}

impl<Trans: Transport> Subscriber<Trans>
{
    /// Create a new Subscriber instance, generate new MSS keypair and optionally NTRU keypair.
    ///
    /// # Arguments
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `encoding` - A string slice representing the encoding type for the message [supported: utf-8]
    /// * `payload_length` - Maximum size in bytes of payload per message chunk [1-1024],
    /// * `transport` - Transport object used for sending and receiving
    ///
    pub fn new(seed: &str, encoding: &str, payload_length: usize, transport: Trans) -> Self {
        let user = User::new(seed, encoding, payload_length, false, transport);
        Self { user }
    }

    /// Returns a boolean representing whether an Announcement message has been processed
    pub fn is_registered(&self) -> bool {
        self.user.is_registered()
    }

    /// Clears inner state except for own keys and link store.
    pub fn unregister(&mut self) {
        self.user.unregister()
    }

    /// Fetch the user ed25519 public key
    pub fn get_pk(&self) -> &ed25519::PublicKey {
        self.user.get_pk()
    }

    /// Fetch the Address (application instance) of the channel.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    /// Return boolean representing the sequencing nature of the channel
    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    /// Create and Send a Subscribe message to a Channel app instance.
    ///
    /// # Arguments
    /// * `link_to` - Address of the Channel Announcement message
    ///
    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address> {
        self.user.send_subscribe(link_to)
    }

    /// Create and send a signed packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    ///
    pub fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_tagged_packet(link_to, public_payload, masked_payload)
    }

    /// Create and send a tagged packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    ///
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

    /// Receive and Process an announcement message.
    ///
    /// # Arguments
    /// * `link_to` - Address of the Channel Announcement message
    ///
    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        self.user.receive_announcement(link)
    }

    /// Receive and process a keyload message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        self.user.receive_keyload(link)
    }

    /// Receive and process a signed packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link)
    }

    /// Receive and process a tagged packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link)
    }

    /// Receive and process a sequence message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link)
    }

    /// Stores the provided link to the internal sequencing state for the provided participant
    /// [Used for multi-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `pk` - ed25519 Public Key of the sender of the message
    ///   * `link` - Address link to be stored in internal sequence state mapping
    ///
    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: &Address) -> Result<()> {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        Ok(self.user.store_state(pk, link)?)
    }

    /// Stores the provided link and sequence number to the internal sequencing state for all participants
    /// [Used for single-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `link` - Address link to be stored in internal sequence state mapping
    ///   * `seq_num` - New sequence state to be stored in internal sequence state mapping
    ///
    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u32) -> Result<()> {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        Ok(self.user.store_state_for_all(link, seq_num)?)
    }

    /// Generate a vector containing the next sequenced message identifier for each publishing
    /// participant in the channel
    ///
    ///   # Arguments
    ///   * `branching` - Boolean representing the sequencing nature of the channel
    ///
    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, Cursor<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs()
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///   * `pk` - Optional ed25519 Public Key of the sending participant. None if unknown
    ///
    pub fn receive_msg(&mut self, link: &Address, pk: Option<ed25519::PublicKey>) -> Result<UnwrappedMessage> {
        self.user.receive_message(link, pk)
    }

    /// Serialize user state and encrypt it with password.
    ///
    ///   # Arguments
    ///   * `pwd` - Encryption password
    ///
    pub fn export(&self, pwd: &str) -> Result<Vec<u8>> {
        self.user.export(1, pwd)
    }

    /// Deserialize user state and decrypt it with password.
    ///
    ///   # Arguments
    ///   * `bytes` - Encrypted serialized user state
    ///   * `pwd` - Encryption password
    ///   * `tsp` - Transport object
    ///
    pub fn import(bytes: &[u8], pwd: &str, tsp: Trans) -> Result<Self> {
        User::<Trans>::import(bytes, 1, pwd, tsp).map(|user| Self { user })
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
