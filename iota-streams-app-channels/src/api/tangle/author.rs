//! Customize Author with default implementation for use over the Tangle.

use iota_streams_core::Result;
use core::fmt;

use super::*;
use crate::api::tangle::{
    UnwrappedMessage,
    User,
};

use iota_streams_core::prelude::Vec;
use iota_streams_core_edsig::signature::ed25519;

/// Author Object. Contains User API.
pub struct Author<Trans> {
    user: User<Trans>,
}

impl<Trans> Author<Trans>
{
    /// Create a new Author instance, generate new MSS keypair and optionally NTRU keypair.
    ///
    /// # Arguments
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `encoding` - A string slice representing the encoding type for the message [supported: utf-8]
    /// * `payload_length` - Maximum size in bytes of payload per message chunk [1-1024],
    /// * `multi_branching` - Boolean representing use of multi-branch or single-branch sequencing
    /// * `transport` - Transport object used for sending and receiving
    ///
    pub fn new(seed: &str, encoding: &str, payload_length: usize, multi_branching: bool, transport: Trans) -> Self {
        let mut user = User::new(seed, encoding, payload_length, multi_branching, transport);
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Self { user }
    }

    /// Return boolean representing the sequencing nature of the channel
    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    /// Fetch the Address (application instance) of the channel.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    /// Fetch the user ed25519 public key
    pub fn get_pk(&self) -> &ed25519::PublicKey {
        self.user.get_pk()
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

    /// Stores the provided link to the internal sequencing state for the provided participant
    /// [Used for multi-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `pk` - ed25519 Public Key of the sender of the message
    ///   * `link` - Address link to be stored in internal sequence state mapping
    ///
    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: &Address) -> Result<()> {
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
        Ok(self.user.store_state_for_all(link, seq_num)?)
    }

    /// Serialize user state and encrypt it with password.
    ///
    ///   # Arguments
    ///   * `pwd` - Encryption password
    ///
    pub fn export(&self, pwd: &str) -> Result<Vec<u8>> {
        self.user.export(0, pwd)
    }

    /// Deserialize user state and decrypt it with password.
    ///
    ///   # Arguments
    ///   * `bytes` - Encrypted serialized user state
    ///   * `pwd` - Encryption password
    ///   * `tsp` - Transport object
    ///
    pub fn import(bytes: &[u8], pwd: &str, tsp: Trans) -> Result<Self> {
        User::<Trans>::import(bytes, 0, pwd, tsp).map(|user| Self { user })
    }
}

#[cfg(not(feature = "async"))]
impl<Trans: Transport> Author<Trans>
{
    /// Send an announcement message, generating a channel.
    pub fn send_announce(&mut self) -> Result<Address> {
        self.user.send_announce()
    }

    /// Create and send a new keyload for a list of subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `psk_ids` - Vector of Pre-shared key ids to be included in message
    ///  * `ke_pks`  - Vector of Public Keys to be included in message
    ///
    pub fn send_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload(link_to, psk_ids, ke_pks)
    }

    /// Create and send keyload for all subscribed subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///
    pub fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload_for_everyone(link_to)
    }

    /// Create and send a signed packet.
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

    /// Create and send a tagged packet.
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


    /// Receive and process a subscribe message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        self.user.receive_subscribe(link)
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

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs()
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///
    pub fn receive_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.receive_message(link)
    }

    // Unsubscribe a subscriber
    // pub pub fn receive_unsubscribe(&mut self, link: Address) -> Result<()> {
    // self.user.handle_unsubscribe(link, MsgInfo::Unsubscribe)
    // }
}

#[cfg(feature = "async")]
impl<Trans: Transport> Author<Trans>
{
    /// Send an announcement message, generating a channel.
    pub async fn send_announce(&mut self) -> Result<Address> {
        self.user.send_announce().await
    }

    /// Create and send a new keyload for a list of subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `psk_ids` - Vector of Pre-shared key ids to be included in message
    ///  * `ke_pks`  - Vector of Public Keys to be included in message
    ///
    pub async fn send_keyload(
        &mut self,
        link_to: &Address,
        psk_ids: &PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload(link_to, psk_ids, ke_pks).await
    }

    /// Create and send keyload for all subscribed subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///
    pub async fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload_for_everyone(link_to).await
    }

    /// Create and send a signed packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    ///
    pub async fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_signed_packet(link_to, public_payload, masked_payload).await
    }

    /// Create and send a tagged packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    ///
    pub async fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user.send_tagged_packet(link_to, public_payload, masked_payload).await
    }

    /// Receive and process a subscribe message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub async fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        self.user.receive_subscribe(link).await
    }

    /// Receive and process a signed packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub async fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link).await
    }

    /// Receive and process a tagged packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub async fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link).await
    }

    /// Receive and process a sequence message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    ///
    pub async fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link).await
    }

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub async fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs().await
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///   * `pk` - Optional ed25519 Public Key of the sending participant. None if unknown
    ///
    pub async fn receive_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.receive_message(link).await
    }

    // Unsubscribe a subscriber
    // pub async fn receive_unsubscribe(&mut self, link: Address) -> Result<()> {
    // self.user.handle_unsubscribe(link, MsgInfo::Unsubscribe).await
    // }
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
