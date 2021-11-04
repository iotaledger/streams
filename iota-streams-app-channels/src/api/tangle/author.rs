//! Customize Author with default implementation for use over the Tangle.

use core::fmt;
use iota_streams_core::Result;

use super::*;
use crate::api::tangle::{
    ChannelType,
    UnwrappedMessage,
    User,
};

use iota_streams_app::id::identifier::Identifier;
#[cfg(feature = "use-did")]
use iota_streams_app::id::DIDInfo;
#[cfg(all(feature = "account", feature = "use-did"))]
use iota_streams_core::iota_identity::account::Account;
#[cfg(feature = "use-did")]
use iota_streams_core::iota_identity::crypto::KeyPair as DIDKeyPair;
use iota_streams_core::{
    panic_if_not,
    prelude::{
        String,
        Vec,
    },
    psk::{
        Psk,
        PskId,
    },
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

/// Author Object. Contains User API.
pub struct Author<Trans> {
    user: User<Trans>,
}

impl<Trans> Author<Trans> {
    #[cfg(not(feature = "use-did"))]
    /// Create a new Author instance, generate new Ed25519 key pair.
    ///
    /// # Arguments
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `encoding` - A string slice representing the encoding type for the message [supported: utf-8]
    /// * `payload_length` - Maximum size in bytes of payload per message chunk [1-1024],
    /// * `multi_branching` - Boolean representing use of multi-branch or single-branch sequencing
    /// * `transport` - Transport object used for sending and receiving
    pub fn new(seed: &str, channel_type: ChannelType, transport: Trans) -> Self {
        let mut user = User::new(seed, channel_type, transport);
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Self { user }
    }

    /// Returns a clone of the transport object
    pub fn get_transport(&self) -> &Trans {
        self.user.get_transport()
    }

    /// Return boolean representing the sequencing nature of the channel
    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    /// Return boolean representing whether the implementation type is single depth
    pub fn is_single_depth(&self) -> bool {
        self.user.is_single_depth()
    }

    /// Fetch the Address (application instance) of the channel.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    /// Fetch the Announcement Link of the channel.
    pub fn announcement_link(&self) -> &Option<TangleAddress> {
        self.user.announcement_link()
    }

    /// Fetch the user ed25519 public key
    pub fn get_public_key(&self) -> &ed25519::PublicKey {
        self.user.get_public_key()
    }

    /// Store a PSK in the user instance
    ///
    ///   # Arguments
    ///   * `pskid` - An identifier representing a pre shared key
    ///   * `psk` - A pre shared key
    pub fn store_psk(&mut self, pskid: PskId, psk: Psk) -> Result<()> {
        self.user.store_psk(pskid, psk, false)
    }

    /// Remove a PSK from the user instance
    ///
    ///   # Arguments
    ///   * `pskid` - An identifier representing a pre shared key
    pub fn remove_psk(&mut self, pskid: PskId) -> Result<()> {
        self.user.remove_psk(pskid)
    }

    /// Store a predefined Subscriber by their public key
    ///
    ///   # Arguments
    ///   * `pk` - ed25519 public key of known subscriber
    pub fn store_new_subscriber(&mut self, pk: PublicKey) -> Result<()> {
        self.user.store_new_subscriber(pk)
    }

    /// Remove a Subscriber from the user instance
    ///
    ///   # Arguments
    ///   * `pk` - ed25519 public key of known subscriber
    pub fn remove_subscriber(&mut self, pk: PublicKey) -> Result<()> {
        self.user.remove_subscriber(pk)
    }

    /// Generate a vector containing the next sequenced message identifier for each publishing
    /// participant in the channel
    ///
    ///   # Arguments
    ///   * `branching` - Boolean representing the sequencing nature of the channel
    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(Identifier, Cursor<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    /// Stores the provided link to the internal sequencing state for the provided participant
    /// [Used for multi-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `id` - Identifier of the sender of the message
    ///   * `ke_pk` - x25519 Public Key of the sender of the message
    ///   * `link` - Address link to be stored in internal sequence state mapping
    pub fn store_state(&mut self, id: Identifier, ke_pk: x25519::PublicKey, link: &Address) -> Result<()> {
        self.user.store_state(id, ke_pk, link)
    }

    /// Stores the provided link and sequence number to the internal sequencing state for all participants
    /// [Used for single-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `link` - Address link to be stored in internal sequence state mapping
    ///   * `seq_num` - New sequence state to be stored in internal sequence state mapping
    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u32) -> Result<()> {
        self.user.store_state_for_all(link, seq_num)
    }

    /// Fetches the latest PublicKey -> Cursor state mapping from the implementation, allowing the
    /// user to see the latest messages present from each publisher
    pub fn fetch_state(&self) -> Result<Vec<(String, Cursor<Address>)>> {
        let state_list = self.user.fetch_state()?;
        let mut state = Vec::new();
        for (pk, cursor) in state_list {
            state.push((hex::encode(pk.to_bytes()), cursor))
        }
        Ok(state)
    }

    /// Resets the cursor state storage to allow an Author to retrieve all messages in a channel
    /// from scratch
    pub fn reset_state(&mut self) -> Result<()> {
        self.user.reset_state()
    }

    /// Serialize user state and encrypt it with password.
    ///
    ///   # Arguments
    ///   * `pwd` - Encryption password
    pub async fn export(&self, pwd: &str) -> Result<Vec<u8>> {
        self.user.export(0, pwd).await
    }

    /// Deserialize user state and decrypt it with password.
    ///
    ///   # Arguments
    ///   * `bytes` - Encrypted serialized user state
    ///   * `pwd` - Encryption password
    ///   * `tsp` - Transport object
    pub async fn import(bytes: &[u8], pwd: &str, tsp: Trans) -> Result<Self> {
        User::<Trans>::import(bytes, 0, pwd, tsp)
            .await
            .map(|user| Self { user })
    }
}

#[cfg(feature = "use-did")]
impl<Trans: Transport + Clone> Author<Trans> {
    #[cfg(feature = "use-did")]
    /// Create a new Author instance, generate new Ed25519 key pair.
    ///
    /// # Arguments
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `encoding` - A string slice representing the encoding type for the message [supported: utf-8]
    /// * `payload_length` - Maximum size in bytes of payload per message chunk [1-1024],
    /// * `multi_branching` - Boolean representing use of multi-branch or single-branch sequencing
    /// * `transport` - Transport object used for sending and receiving
    pub fn new(seed: &str, channel_type: ChannelType, transport: Trans) -> Self {
        let mut user = User::new(seed, channel_type, transport);
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Self { user }
    }

    #[cfg(feature = "account")]
    pub async fn new_with_account(
        account: Account,
        channel_type: ChannelType,
        transport: Trans,
        did_info: DIDInfo,
    ) -> Result<Self> {
        let mut user = User::new_with_account(account, channel_type, transport, did_info).await?;
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Ok(Self { user })
    }

    pub async fn new_with_did(
        seed: &str,
        channel_type: ChannelType,
        transport: Trans,
        did_info: DIDInfo,
        did_keypair: &DIDKeyPair,
    ) -> Result<(Self, ed25519::Keypair)> {
        let (mut user, user_keypair) = User::new_with_did(seed, channel_type, transport, did_info, did_keypair).await?;
        let channel_idx = 0_u64;
        let _ = user.user.create_channel(channel_idx);
        Ok((Self { user }, user_keypair))
    }
}

impl<Trans: Transport + Clone> Author<Trans> {
    /// Generates a new Author implementation from input. If the announcement message generated by
    /// this instance matches that of an existing (and provided) announcement link, the user will
    /// sync to the latest state
    ///
    ///  # Arguements
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `announcement` - An existing announcement message link for validation of ownership
    /// * `multi_branching` - Boolean representing use of multi-branch or single-branch sequencing
    /// * `transport` - Transport object used for sending and receiving
    pub async fn recover(
        seed: &str,
        announcement: &Address,
        channel_type: ChannelType,
        transport: Trans,
    ) -> Result<Self> {
        let mut author = Author::new(seed, channel_type, transport);

        let ann = author.user.user.announce().await?;
        let retrieved: Message = author.user.transport.recv_message(announcement).await?;
        panic_if_not(retrieved.binary == ann.message);

        author.user.commit_wrapped(ann.wrapped, MsgInfo::Announce)?;

        Ok(author)
    }

    #[cfg(feature = "use-did")]
    pub async fn recover_with_did(
        seed: &str,
        channel_type: ChannelType,
        announcement: &Address,
        transport: Trans,
        did_info: DIDInfo,
    ) -> Result<Self> {
        let mut author = User::recover_with_did(seed, channel_type, transport, did_info).await?;
        author.user.create_channel(0_u64)?;

        let ann = author.user.announce().await?;
        let retrieved: Message = author.transport.recv_message(announcement).await?;
        panic_if_not(retrieved.binary == ann.message);

        author.commit_wrapped(ann.wrapped, MsgInfo::Announce)?;

        Ok(Self { user: author })
    }

    /// Send an announcement message, generating a channel.
    pub async fn send_announce(&mut self) -> Result<Address> {
        self.user.send_announce().await
    }

    /// Create and send a new keyload for a list of subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `keys`  - Iterable of [`Identifier`] to be included in message
    pub async fn send_keyload<'a, I>(&mut self, link_to: &Address, keys: I) -> Result<(Address, Option<Address>)>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        self.user.send_keyload(link_to, keys).await
    }

    /// Create and send keyload for all subscribed subscribers.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    pub async fn send_keyload_for_everyone(&mut self, link_to: &Address) -> Result<(Address, Option<Address>)> {
        self.user.send_keyload_for_everyone(link_to).await
    }

    /// Create and send a signed packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub async fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user
            .send_signed_packet(link_to, public_payload, masked_payload)
            .await
    }

    /// Create and send a tagged packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub async fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        self.user
            .send_tagged_packet(link_to, public_payload, masked_payload)
            .await
    }

    /// Receive and process a subscribe message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_subscribe(&mut self, link: &Address) -> Result<()> {
        self.user.receive_subscribe(link).await
    }

    /// Receive and process an unsubscribe message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_unsubscribe(&mut self, link: &Address) -> Result<()> {
        self.user.receive_unsubscribe(link).await
    }

    /// Receive and process a signed packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_signed_packet(&mut self, link: &Address) -> Result<(Identifier, Bytes, Bytes)> {
        self.user.receive_signed_packet(link).await
    }

    /// Receive and process a tagged packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link).await
    }

    /// Receive and process a sequence message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link).await
    }

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub async fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs().await
    }

    /// Iteratively fetches next message until no new messages can be found, and return a vector
    /// containing all of them.
    pub async fn fetch_all_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        let mut exists = true;
        let mut msgs = Vec::new();
        while exists {
            let next_msgs = self.fetch_next_msgs().await;
            if next_msgs.is_empty() {
                exists = false
            } else {
                msgs.extend(next_msgs)
            }
        }
        msgs
    }

    /// Retrieves the previous message from the message specified (provided the user has access to it)
    pub async fn fetch_prev_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.fetch_prev_msg(link).await
    }

    /// Retrieves a specified number of previous messages from an original specified messsage link
    pub async fn fetch_prev_msgs(&mut self, link: &Address, max: usize) -> Result<Vec<UnwrappedMessage>> {
        self.user.fetch_prev_msgs(link, max).await
    }

    /// Iteratively fetches next messages until internal state has caught up
    pub async fn sync_state(&mut self) {
        let mut exists = true;
        while exists {
            exists = !self.fetch_next_msgs().await.is_empty()
        }
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///   * `pk` - Optional ed25519 Public Key of the sending participant. None if unknown
    pub async fn receive_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.receive_message(link).await
    }

    // Unsubscribe a subscriber
    // pub async fn receive_unsubscribe(&mut self, link: Address) -> Result<()> {
    // self.user.handle_unsubscribe(link, MsgInfo::Unsubscribe).await
    // }

    /// Receive and process a message with a known anchor link and message number. This can only
    /// be used if the channel is a single depth channel.
    ///
    ///   # Arguments
    ///   * `anchor_link` - Address of the anchor message for the channel
    ///   * `msg_num` - Sequence of sent message (not counting announce or any keyloads)
    pub async fn receive_msg_by_sequence_number(
        &mut self,
        anchor_link: &Address,
        msg_num: u32,
    ) -> Result<UnwrappedMessage> {
        self.user.receive_msg_by_sequence_number(anchor_link, msg_num).await
    }
}

impl<Trans: Clone> fmt::Display for Author<Trans> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(&self.user.user.key_pairs.id.to_bytes()),
            self.user.user.key_store
        )
    }
}
