// Rust
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{Debug, Formatter, Result as FormatResult};

// 3rd-party
use async_trait::async_trait;
use futures::{future, TryStreamExt};
use hashbrown::{HashMap, HashSet};
use rand::{rngs::StdRng, Rng, SeedableRng};

// IOTA

// Streams
use lets::{
    address::{Address, AppAddr, MsgId},
    id::{Identifier, Identity, PermissionDuration, Permissioned, Psk, PskId},
    message::{
        ContentSizeof, ContentUnwrap, ContentWrap, Message as LetsMessage, PreparsedMessage, Topic, TopicHash,
        TransportMessage, HDF, PCF,
    },
    transport::Transport,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask, Squeeze},
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    KeccakF1600, Spongos, SpongosRng,
};

// Local
use crate::{
    api::{
        cursor_store::CursorStore, message::Message, message_builder::MessageBuilder, messages::Messages,
        send_response::SendResponse, user_builder::UserBuilder,
    },
    message::{
        announcement, branch_announcement, keyload, message_types, signed_packet, subscription, tagged_packet,
        unsubscription,
    },
    Error, Result,
};

const ANN_MESSAGE_NUM: usize = 0; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: usize = 0; // Subscription is always the first message of subscribers
const INIT_MESSAGE_NUM: usize = 1; // First non-reserved message number

/// The state of a user, mapping publisher cursors and link states for message processing.
#[derive(PartialEq, Eq, Default)]
struct State {
    /// Users' [`Identity`] information, contains keys and logic for signing and verification.
    ///
    /// None if the user is not created with an identity
    user_id: Option<Identity>,

    /// [`Address`] of the stream announcement message.
    ///
    /// None if channel is not created or user is not subscribed.
    stream_address: Option<Address>,

    /// [`Identifier`] of the channel author.
    ///
    /// None if channel is not created or user is not subscribed.
    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no) mapped
    /// by branch topic Vec.
    cursor_store: CursorStore,

    /// Mapping of trusted pre shared keys and identifiers.
    psk_store: HashMap<PskId, Psk>,

    /// List of Subscribed [Identifiers](`Identifier`).
    subscribers: HashSet<Identifier>,

    /// Mapping of message links ([`MsgId`]) and [`Spongos`] states. Messages are built from the
    /// [`Spongos`] state of a previous message. If the state for a link is not stored, then a
    /// message cannot be formed or processed.
    spongos_store: HashMap<MsgId, Spongos>,

    base_branch: Topic,

    /// Users' [`Spongos`] Storage configuration. If lean, only the announcement message and latest
    /// branch message spongos state is stored. This reduces the overall size of the user
    /// implementation over time. If not lean, all spongos states processed by the user will be
    /// stored.
    lean: bool,

    /// List of known branch topics.
    topics: HashSet<Topic>,
}

/// Public `API` Client for participation in a `Streams` channel.
pub struct User<T> {
    /// A transport client for sending and receiving messages.
    transport: T,
    /// The internal [state](`State`) of the user, containing message state mappings and publisher
    /// cursors for message processing.
    state: State,
}

impl User<()> {
    /// Creates a new [`UserBuilder`] instance.
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T> User<T> {
    /// Creates a new [`User`] with the provided configurations.
    ///
    /// # Arguments
    /// * `user_id`: The user's [`Identity`]. This is used to sign messages.
    /// * `psks`: A list of trusted pre shared keys.
    /// * `transport`: The transport to use for sending and receiving messages.
    /// * `lean`: If true, the client will store only required message states.
    pub(crate) fn new<Psks>(user_id: Option<Identity>, psks: Psks, transport: T, lean: bool) -> Self
    where
        Psks: IntoIterator<Item = (PskId, Psk)>,
    {
        let mut psk_store = HashMap::new();
        let subscribers = HashSet::new();

        // Store any pre shared keys
        psks.into_iter().for_each(|(pskid, psk)| {
            psk_store.insert(pskid, psk);
        });

        Self {
            transport,
            state: State {
                user_id,
                cursor_store: CursorStore::new(),
                psk_store,
                subscribers,
                spongos_store: Default::default(),
                stream_address: None,
                author_identifier: None,
                base_branch: Default::default(),
                lean,
                topics: Default::default(),
            },
        }
    }

    /// Returns a reference to the [User's](`User`) [`Identifier`] if any.
    pub fn identifier(&self) -> Option<&Identifier> {
        self.identity().map(|id| id.identifier())
    }

    /// Returns a reference to the [User's](`User`) [`Identity`] if any.
    fn identity(&self) -> Option<&Identity> {
        self.state.user_id.as_ref()
    }

    /// Returns a reference to the [User's](`User`) [permission](`Permissioned`) for a given branch
    /// if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    pub fn permission(&self, topic: &Topic) -> Option<&Permissioned<Identifier>> {
        self.identifier()
            .and_then(|id| self.state.cursor_store.get_permission(topic, id))
    }

    /// Returns the [User's](`User`) cursor for a given branch if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    fn cursor(&self, topic: &Topic) -> Option<usize> {
        self.identifier()
            .and_then(|id| self.state.cursor_store.get_cursor(topic, id))
    }

    /// Returns the [User's](`User`) next cursor for a given branch. Errors if there is
    /// no cursor present for the [`User`] in [`CursorStore`].
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to check
    fn next_cursor(&self, topic: &Topic) -> Result<usize> {
        self.cursor(topic).map(|c| c + 1).ok_or(Error::NoCursor(topic.clone()))
    }

    /// Returns a reference to the base branch [`Topic`] for the stream.
    pub fn base_branch(&self) -> &Topic {
        &self.state.base_branch
    }

    /// Returns a reference to the announcement message [`Address`] for the stream if any.
    pub fn stream_address(&self) -> Option<Address> {
        self.state.stream_address
    }

    /// Returns a reference to the [`User`] transport client.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the [`User`] transport client.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns an iterator over all known branch [topics](`Topic`)
    pub fn topics(&self) -> impl Iterator<Item = &Topic> + ExactSizeIterator {
        self.state.topics.iter()
    }

    /// Iterates through known topics, returning the [`Topic`] that matches the [`TopicHash`]
    /// provided if any
    ///
    /// # Arguments
    /// * `hash`: The [`TopicHash`] from a message header
    pub(crate) fn topic_by_hash(&self, hash: &TopicHash) -> Option<Topic> {
        self.topics().find(|t| &TopicHash::from(*t) == hash).cloned()
    }

    /// Returns true if [`User`] lean state configuration is true
    fn lean(&self) -> bool {
        self.state.lean
    }

    /// Returns an iterator over [`CursorStore`], producing tuples of [`Topic`], [`Permissioned`]
    /// [`Identifier`], and the cursor. Used by [`Messages`] streams to find next messages.
    pub(crate) fn cursors(&self) -> impl Iterator<Item = (&Topic, &Permissioned<Identifier>, usize)> + '_ {
        self.state.cursor_store.cursors()
    }

    /// Returns an iterator over a [`Topic`] mapped branch in [`CursorStore`], producing tuples of
    /// [`Permissioned`][`Identifier`] and a cursor. Used to carry permissions forward through
    /// branch declarations. Returns an error if the [`Topic`] is not found in store.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to fetch cursors for
    fn cursors_by_topic(&self, topic: &Topic) -> Result<impl Iterator<Item = (&Permissioned<Identifier>, &usize)>> {
        self.state
            .cursor_store
            .cursors_by_topic(topic)
            .ok_or(Error::TopicNotFound(topic.clone()))
    }

    /// Returns an iterator over known subscriber [identifiers](`Identifier`)
    pub fn subscribers(&self) -> impl Iterator<Item = &Identifier> + Clone + '_ {
        self.state.subscribers.iter()
    }

    /// If the subscriber is not readonly and the [`Permissioned`] is not tracked or the
    /// [`Permissioned`] is tracked and not equal to the provided subscriber [`Permissioned`],
    /// then the cursor should be stored.
    ///
    /// # Arguments:
    /// * `topic`: The topic of the branch to be stored in.
    /// * `permission`: The [`Permissioned`] to check.
    fn should_store_cursor(&self, topic: &Topic, permission: Permissioned<&Identifier>) -> bool {
        let self_permission = self.state.cursor_store.get_permission(topic, permission.identifier());
        let tracked_and_equal = self_permission.is_some() && (self_permission.unwrap().as_ref() == permission);
        !permission.is_readonly() && !tracked_and_equal
    }

    /// Store a new [`Spongos`] state. If the [`User`] lean state configuration is set to true, and
    /// if the linked message is not the stream announcement message, remove the previous message
    /// from store.
    ///
    /// # Arguments:
    /// * `msg_address`: The [`Address`] of the message that we're storing the [`Spongos`] for.
    /// * `spongos`: The [`Spongos`] state to be stored.
    /// * `linked_msg_address`: The address of the message that the spongos is linked to.
    fn store_spongos(&mut self, msg_address: MsgId, spongos: Spongos, linked_msg_address: MsgId) {
        let is_stream_address = self
            .stream_address()
            .map_or(false, |stream_address| stream_address.relative() == linked_msg_address);
        // Do not remove announcement message from store
        if self.lean() && !is_stream_address {
            self.state.spongos_store.remove(&linked_msg_address);
        }

        self.state.spongos_store.insert(msg_address, spongos);
    }

    /// Store a new subscriber [`Identifier`] in state. Returns true if subscriber was not present.
    pub fn add_subscriber(&mut self, subscriber: Identifier) -> bool {
        self.state.subscribers.insert(subscriber)
    }

    /// Remove a subscriber [`Identifier`] from state. Returns true if the subscriber was present.
    pub fn remove_subscriber(&mut self, id: &Identifier) -> bool {
        self.state.subscribers.remove(id)
    }

    /// Store a new [Pre-Shared Key](`Psk`) in state. Returns true if [`Psk`] was not present.
    pub fn add_psk(&mut self, psk: Psk) -> bool {
        self.state.psk_store.insert(psk.to_pskid(), psk).is_none()
    }

    /// Remove a [`Psk`] from state by its [identifier](`PskId`). Returns true if the [`Psk`] was
    /// present.
    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.state.psk_store.remove(&pskid).is_some()
    }

    /// Sets the latest message link for a specified branch. If the branch does not exist, it is
    /// created.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch
    /// * `latest_link`: The [`MsgId`] link that will be set
    fn set_latest_link(&mut self, topic: Topic, latest_link: MsgId) {
        self.state.cursor_store.set_latest_link(topic, latest_link)
    }

    /// Returns the latest [`MsgId`] link for a specified branch, if any
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch
    fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.state.cursor_store.get_latest_link(topic)
    }

    /// Parse and process a [`TransportMessage`] dependent on its type.
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message to process
    /// * `msg`: The raw [`TransportMessage`]
    pub(crate) async fn handle_message(&mut self, address: Address, msg: TransportMessage) -> Result<Message> {
        let preparsed = msg
            .parse_header()
            .await
            .map_err(|e| Error::Unwrapping("header", address, e))?;

        match preparsed.header().message_type() {
            message_types::ANNOUNCEMENT => self.handle_announcement(address, preparsed).await,
            message_types::BRANCH_ANNOUNCEMENT => self.handle_branch_announcement(address, preparsed).await,
            message_types::SUBSCRIPTION => self.handle_subscription(address, preparsed).await,
            message_types::UNSUBSCRIPTION => self.handle_unsubscription(address, preparsed).await,
            message_types::KEYLOAD => self.handle_keyload(address, preparsed).await,
            message_types::SIGNED_PACKET => self.handle_signed_packet(address, preparsed).await,
            message_types::TAGGED_PACKET => self.handle_tagged_packet(address, preparsed).await,
            unknown => Err(Error::MessageTypeUnknown(unknown)),
        }
    }

    /// Processes an announcement message, binding a [`User`] to the stream announced in the
    /// message.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_announcement(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Check Topic
        let publisher = preparsed.header().publisher().clone();

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed
            .unwrap(announcement)
            .await
            .map_err(|e| Error::Unwrapping("announcement", address, e))?;

        let topic = message.payload().content().topic();
        // Insert new branch into store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());

        // When handling an announcement it means that no cursors have been stored, as no topics are
        // known yet. The message must be unwrapped to retrieve the initial topic before storing cursors
        self.state
            .cursor_store
            .insert_cursor(topic, Permissioned::Admin(publisher), INIT_MESSAGE_NUM);

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        let author_id = message.payload().content().author_id().clone();

        // Update branch links
        self.set_latest_link(topic.clone(), address.relative());
        self.state.author_identifier = Some(author_id);
        self.state.base_branch = topic.clone();
        self.state.stream_address = Some(address);

        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a branch announcement message, creating a new branch in [`CursorStore`], carrying
    /// over mapped permissions and cursors from the previous branch.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_branch_announcement(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Retrieve header values
        let prev_topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;

        let publisher = preparsed.header().publisher().clone();
        let cursor = preparsed.header().sequence();

        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        let permission = self
            .state
            .cursor_store
            .get_permission(&prev_topic, &publisher)
            .ok_or(Error::NoCursor(prev_topic.clone()))?
            .clone();
        self.state.cursor_store.insert_cursor(&prev_topic, permission, cursor);

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("branch announcement", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let branch_announcement = branch_announcement::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(branch_announcement)
            .await
            .map_err(|e| Error::Unwrapping("branch announcement", address, e))?;

        let new_topic = message.payload().content().new_topic();
        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);
        // Insert new branch into store
        self.state.cursor_store.new_branch(new_topic.clone());
        self.state.topics.insert(new_topic.clone());
        // Collect permissions from previous branch and clone them into new branch
        let prev_permissions = self
            .cursors_by_topic(&prev_topic)?
            .map(|(id, _)| id.clone())
            .collect::<Vec<Permissioned<Identifier>>>();
        for id in prev_permissions {
            self.state.cursor_store.insert_cursor(new_topic, id, INIT_MESSAGE_NUM);
        }

        // Update branch links
        self.set_latest_link(new_topic.clone(), address.relative());

        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a [`User`] subscription message, storing the subscriber [`Identifier`].
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_subscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as cursor is only tracked for subscribers with write permissions

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("subscription", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_ke_sk = &self
            .identity()
            .ok_or(Error::NoIdentity("Derive a secret key"))?
            .ke_sk()
            .map_err(|_| Error::NoSecretKey)?;

        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, _spongos) = preparsed
            .unwrap(subscription)
            .await
            .map_err(|e| Error::Unwrapping("subscription", address, e))?;

        // Store spongos
        // Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers

        // Store message content into stores
        let subscriber_identifier = message.payload().content().subscriber_identifier();
        self.add_subscriber(subscriber_identifier.clone());

        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a [`User`] unsubscription message, removing the subscriber [`Identifier`] from
    /// store.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_unsubscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as user is unsubscribing

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("unsubscribe", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                *spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(unsubscription)
            .await
            .map_err(|e| Error::Unwrapping("unsubscribe", address, e))?;

        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);

        // Store message content into stores
        self.remove_subscriber(message.payload().content().subscriber_identifier());

        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a keyload message, updating store to include the contained list of
    /// [permissions](`Permissioned`). All keyload messages are linked to the announcement
    /// message to ensure they can always be read by a [`User`] that can sequence up to it.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_keyload(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        let stream_address = self.stream_address().ok_or(Error::NoStream("handling a keyload"))?;

        let topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;
        let publisher = preparsed.header().publisher().clone();
        // Confirm keyload came from administrator
        if !self
            .state
            .cursor_store
            .get_permission(&topic, &publisher)
            .ok_or(Error::NoCursor(topic.clone()))?
            .is_admin()
        {
            return Err(Error::WrongRole("admin", publisher, "receive keyload"));
        }
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(&topic, Permissioned::Admin(publisher), preparsed.header().sequence());

        // Unwrap message
        // Ok to unwrap since an author identifier is set at the same time as the stream address
        let author_identifier = self.state.author_identifier.as_ref().unwrap();
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let keyload = keyload::Unwrap::new(
            &mut announcement_spongos,
            self.state.user_id.as_ref(),
            author_identifier,
            &self.state.psk_store,
        );
        let (message, spongos) = preparsed
            .unwrap(keyload)
            .await
            .map_err(|e| Error::Unwrapping("keyload", address, e))?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        let subscribers = message.payload().content().subscribers();

        // If a branch admin does not include a user in the keyload, any further messages sent by
        // the user will not be received by the others, so remove them from the publisher pool
        let stored_subscribers: Vec<(Permissioned<Identifier>, usize)> = self
            .cursors_by_topic(&topic)?
            .map(|(perm, cursor)| (perm.clone(), *cursor))
            .collect();

        for (perm, cursor) in stored_subscribers {
            if !(perm.identifier() == author_identifier
                || subscribers.iter().any(|p| p.identifier() == perm.identifier()))
            {
                self.state
                    .cursor_store
                    .insert_cursor(&topic, Permissioned::Read(perm.identifier().clone()), cursor);
            }
        }

        // Store message content into stores
        for subscriber in subscribers {
            if self.should_store_cursor(&topic, subscriber.as_ref()) {
                self.state
                    .cursor_store
                    .insert_cursor(&topic, subscriber.clone(), INIT_MESSAGE_NUM);
            }
        }

        // Have to make message before setting branch links due to immutable borrow in keyload::unwrap
        let final_message = Message::from_lets_message(address, message);
        // Update branch links
        self.set_latest_link(topic, address.relative());
        Ok(final_message)
    }

    /// Processes a signed packet message, retrieving the public and masked payloads, and verifying
    /// the message signature against the publisher [`Identifier`].
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_signed_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        let topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;
        let publisher = preparsed.header().publisher();
        let permission = self
            .state
            .cursor_store
            .get_permission(&topic, publisher)
            .ok_or(Error::NoCursor(topic.clone()))?
            .clone();
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(&topic, permission, preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("signed", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let signed_packet = signed_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(signed_packet)
            .await
            .map_err(|e| Error::Unwrapping("signed packet", address, e))?;

        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);

        // Store message content into stores
        self.set_latest_link(topic, address.relative());
        Ok(Message::from_lets_message(address, message))
    }

    /// Processes a tagged packet message, retrieving the public and masked payloads.
    ///
    /// # Arguments:
    /// * `address`: The [`Address`] of the message to be processed
    /// * `preparsed`: The [`PreparsedMessage`] to be processed
    async fn handle_tagged_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        let topic = self
            .topic_by_hash(preparsed.header().topic_hash())
            .ok_or(Error::UnknownTopic(*preparsed.header().topic_hash()))?;
        let publisher = preparsed.header().publisher();
        let permission = self
            .state
            .cursor_store
            .get_permission(&topic, publisher)
            .ok_or(Error::NoCursor(topic.clone()))?
            .clone();
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(&topic, permission, preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed
            .header()
            .linked_msg_address()
            .ok_or(Error::NotLinked("tagged", address))?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed
            .unwrap(tagged_packet)
            .await
            .map_err(|e| Error::Unwrapping("tagged packet", address, e))?;

        // Store spongos
        self.store_spongos(address.relative(), spongos, linked_msg_address);

        // Store message content into stores
        self.set_latest_link(topic, address.relative());

        Ok(Message::from_lets_message(address, message))
    }

    /// Creates an encrypted, serialised representation of a [`User`] `State` for backup and
    /// recovery.
    ///
    /// # Arguments
    /// * `pwd`: The password to encrypt the `State` with
    pub async fn backup<P>(&mut self, pwd: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.state).await.map_err(Error::Spongos)?;
        let buf_size = ctx.finalize() + 32; // State + Mac Size

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))
            .map_err(Error::Spongos)?
            .commit()
            .map_err(Error::Spongos)?
            .squeeze(&Mac::new(32))
            .map_err(Error::Spongos)?;
        ctx.wrap(&mut self.state).await.map_err(Error::Spongos)?;
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );

        Ok(buf)
    }

    /// Restore a [`User`] from an encrypted binary stream using the provided password and transport
    /// client.
    ///
    /// # Arguments
    /// * `backup`: Encrypted binary stream of backed up `State`.
    /// * `pwd`: The decryption password.
    /// * `transport`: The transport client for sending and receiving messages.
    pub async fn restore<B, P>(backup: B, pwd: P, transport: T) -> Result<Self>
    where
        P: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut ctx = unwrap::Context::new(backup.as_ref());
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))
            .map_err(Error::Spongos)?
            .commit()
            .map_err(Error::Spongos)?
            .squeeze(&Mac::new(32))
            .map_err(Error::Spongos)?;
        let mut state = State::default();
        ctx.unwrap(&mut state).await.map_err(Error::Spongos)?;
        Ok(User { transport, state })
    }
}

impl<T> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage>,
{
    /// Receive a raw message packet using the internal [`Transport`] client
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message to be retrieved.
    pub async fn receive_message(&mut self, address: Address) -> Result<Message>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage>,
    {
        let msg = self
            .transport
            .recv_message(address)
            .await
            .map_err(|e| Error::Transport(address, "receive message", e))?;
        self.handle_message(address, msg).await
    }

    /// Start a [`Messages`] stream to traverse the channel messages
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn messages(&mut self) -> Messages<T> {
        Messages::new(self)
    }

    /// Iteratively fetches all the next messages until internal state has caught up
    ///
    /// If succeeded, returns the number of messages advanced.
    pub async fn sync(&mut self) -> Result<usize> {
        // ignoring the result is sound as Drain::Error is Infallible
        self.messages()
            .try_fold(0, |n, _| future::ok(n + 1))
            .await
            .map_err(Error::Messages)
    }

    /// Iteratively fetches all the pending messages from the transport
    ///
    /// Return a vector with all the messages collected. This is a convenience
    /// method around the [`Messages`] stream. Check out its docs for more
    /// advanced usages.
    pub async fn fetch_next_messages(&mut self) -> Result<Vec<Message>> {
        self.messages().try_collect().await.map_err(Error::Messages)
    }
}

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR>,
{
    /// Create and send a stream Announcement message, anchoring the stream for others to attach to.
    /// Errors if the [`User`] is already attached to a stream, or if the message already exists in
    /// the transport layer.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] that will be used for the base branch
    pub async fn create_stream<Top: Into<Topic>>(&mut self, topic: Top) -> Result<SendResponse<TSR>> {
        // Check conditions
        if self.stream_address().is_some() {
            return Err(Error::Setup(
                "Cannot create a channel, user is already registered to channel",
            ));
        }
        // Confirm user has identity
        let identifier = self.identifier().ok_or(Error::NoIdentity("create a stream"))?.clone();
        // Convert topic
        let topic = topic.into();
        // Generate stream address
        let stream_base_address = AppAddr::gen(&identifier, &topic);
        let stream_rel_address = MsgId::gen(stream_base_address, &identifier, &topic, INIT_MESSAGE_NUM);
        let stream_address = Address::new(stream_base_address, stream_rel_address);

        // Prepare HDF and PCF
        let header = HDF::new(message_types::ANNOUNCEMENT, ANN_MESSAGE_NUM, identifier.clone(), &topic);
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(self.identity().unwrap(), &topic));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("wrap announce", e))?;

        // Attempt to send message
        if !self.transport.recv_message(stream_address).await.is_err() {
            return Err(Error::Setup("Cannot create a channel, announce address already in use"));
        }

        let send_response = self
            .transport
            .send_message(stream_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send announce message", e))?;

        // If a message has been sent successfully, insert the base branch into store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());
        // Commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, Permissioned::Admin(identifier.clone()), INIT_MESSAGE_NUM);
        self.state.spongos_store.insert(stream_address.relative(), spongos);

        // Update branch links
        self.set_latest_link(topic.clone(), stream_address.relative());

        // Commit Author Identifier and Stream Address to store
        self.state.stream_address = Some(stream_address);
        self.state.author_identifier = Some(identifier);
        self.state.base_branch = topic;

        Ok(SendResponse::new(stream_address, send_response))
    }

    /// Create and send a new Branch Announcement message, creating a new branch in `CursorStore`
    /// with the previous branches permissions carried forward.
    ///
    /// # Arguments
    /// * `from_topic`: The [`Topic`] of the branch to generate the new branch from.
    /// * `to_topic`: The [`Topic`] of the new branch being created.
    pub async fn new_branch(
        &mut self,
        from_topic: impl Into<Topic>,
        to_topic: impl Into<Topic>,
    ) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or(Error::Setup("before starting a new branch, the stream must be created"))?;
        // Confirm user has identity
        let identifier = self.identifier().ok_or(Error::NoIdentity("create a branch"))?.clone();
        // Check Topic
        let topic: Topic = to_topic.into();
        let prev_topic: Topic = from_topic.into();
        // Check Permission
        let permission = self
            .state
            .cursor_store
            .get_permission(&prev_topic, &identifier)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if permission.is_readonly() {
            return Err(Error::WrongRole("ReadWrite", identifier, "make a new branch"));
        }
        let link_to = self
            .get_latest_link(&prev_topic)
            .ok_or_else(|| Error::TopicNotFound(prev_topic.clone()))?;

        // Update own's cursor
        let user_cursor = self
            .next_cursor(&prev_topic)
            .map_err(|_| Error::NoCursor(prev_topic.clone()))?;
        let msgid = MsgId::gen(stream_address.base(), &identifier, &prev_topic, user_cursor);
        let address = Address::new(stream_address.base(), msgid);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let header = HDF::new(
            message_types::BRANCH_ANNOUNCEMENT,
            user_cursor,
            identifier.clone(),
            &prev_topic,
        )
        .with_linked_msg_address(link_to);
        let content = PCF::new_final_frame().with_content(branch_announcement::Wrap::new(
            &mut linked_msg_spongos,
            self.identity().unwrap(),
            &topic,
        ));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("wrap new branch", e))?;

        if !self.transport.recv_message(address).await.is_err() {
            return Err(Error::AddressUsed("new branch", address));
        }

        let send_response = self
            .transport
            .send_message(address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send new branch message", e))?;

        // If message has been sent successfully, create the new branch in store
        self.state.cursor_store.new_branch(topic.clone());
        self.state.topics.insert(topic.clone());
        // Commit message to stores and update cursors
        self.state.cursor_store.insert_cursor(
            &prev_topic,
            Permissioned::Admin(identifier.clone()),
            self.next_cursor(&prev_topic)?,
        );
        self.state.spongos_store.insert(address.relative(), spongos);
        // Collect permissions from previous branch and clone them into new branch
        let prev_permissions = self
            .cursors_by_topic(&prev_topic)?
            .map(|(id, _)| id.clone())
            .collect::<Vec<Permissioned<Identifier>>>();
        for id in prev_permissions {
            self.state.cursor_store.insert_cursor(&topic, id, INIT_MESSAGE_NUM);
        }

        // Update branch links
        self.state.cursor_store.set_latest_link(topic, address.relative());
        Ok(SendResponse::new(address, send_response))
    }

    /// Create and send a new Subscription message, awaiting the stream author's acceptance into the
    /// stream.
    pub async fn subscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or(Error::Setup("before starting a new branch, the stream must be created"))?;
        // Confirm user has identity
        let user_id = self.identity().ok_or(Error::NoIdentity("subscribe"))?;
        let identifier = user_id.identifier();
        // Get base branch topic
        let base_branch = &self.state.base_branch;
        // Link message to channel announcement
        let link_to = stream_address.relative();
        let rel_address = MsgId::gen(stream_address.base(), identifier, base_branch, SUB_MESSAGE_NUM);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .state
            .author_identifier
            .as_ref()
            .unwrap()
            .ke_pk()
            .await
            .map_err(|_| Error::Setup("Failed to generate Public Key from author identifier"))?;

        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            user_id,
            &author_ke_pk,
        ));
        let header = HDF::new(
            message_types::SUBSCRIPTION,
            SUB_MESSAGE_NUM,
            identifier.clone(),
            base_branch,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, _spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("subscribe", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);

        // Attempt to send message
        let has_msg = self.transport.recv_message(message_address).await;
        if !has_msg.is_err() {
            return Err(Error::AddressUsed("subscribe", message_address));
        }

        let send_response = self
            .transport
            .send_message(message_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(message_address, "send subscribe message", e))?;

        // If message has been sent successfully, commit message to stores
        // - Subscription messages are not stored in the cursor store
        // - Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers
        Ok(SendResponse::new(message_address, send_response))
    }

    /// Create and send a new Unsubscription message, informing the stream author that this [`User`]
    /// instance can be removed from the stream.
    pub async fn unsubscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or(Error::Setup("before unsubscribing, the stream must be created"))?;
        // Confirm user has identity
        let user_id = self.identity().ok_or(Error::NoIdentity("unsubscribe"))?;
        let identifier = user_id.identifier().clone();
        // Get base branch topic
        let base_branch = &self.state.base_branch;
        // Link message to channel announcement
        let link_to = self
            .get_latest_link(base_branch)
            .ok_or_else(|| Error::TopicNotFound(base_branch.clone()))?;

        // Update own's cursor
        let new_cursor = self.next_cursor(base_branch)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, base_branch, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let content = PCF::new_final_frame().with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, user_id));
        let header = HDF::new(
            message_types::UNSUBSCRIPTION,
            new_cursor,
            identifier.clone(),
            base_branch,
        )
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("unsubscribe", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("unsubscribe", message_address));
        }

        let send_response = self
            .transport
            .send_message(message_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send unsubscribe message", e))?;

        // If message has been sent successfully, commit message to stores
        let permission = Permissioned::Read(identifier);
        self.state
            .cursor_store
            .insert_cursor(base_branch, permission, new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        Ok(SendResponse::new(message_address, send_response))
    }

    /// Create and send a new Keyload message, updating the read/write permissions for a specified
    /// branch. All keyload messages are linked to the announcement message to ensure they
    /// can always be read by a [`User`] that can sequence up to it.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    /// * `subscribers`: The updated [`Permissioned`] list for the branch.
    /// * `psk_ids`: A list of [Psk Id's](`PskId`) with read access for the branch.
    pub async fn send_keyload<'a, Subscribers, Psks, Top>(
        &mut self,
        topic: Top,
        subscribers: Subscribers,
        psk_ids: Psks,
    ) -> Result<SendResponse<TSR>>
    where
        Subscribers: IntoIterator<Item = Permissioned<&'a Identifier>> + Clone,
        Subscribers::IntoIter: ExactSizeIterator,
        Top: Into<Topic>,
        Psks: IntoIterator<Item = PskId>,
    {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or(Error::Setup("before sending a keyload, the stream must be created"))?;
        // Confirm user has identity
        let user_id = self.identity().ok_or(Error::NoIdentity("send keyload"))?;
        let identifier = user_id.identifier().clone();
        // Check Topic
        let topic = topic.into();
        // Check Permission
        let permission = self.permission(&topic).ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole("Admin", identifier, "send a keyload"));
        }

        // Link message to edge of branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| Error::TopicNotFound(topic.clone()))?;
        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        // All Keyload messages will attach to stream Announcement message spongos
        let mut announcement_msg_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .ok_or(Error::Setup("a user must keep a stream announcement spongos in store"))?;

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let psk_ids_with_psks = psk_ids
            .into_iter()
            .map(|pskid| Ok((pskid, self.state.psk_store.get(&pskid).ok_or(Error::UnknownPsk(pskid))?)))
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut announcement_msg_spongos,
            subscribers.clone().into_iter().collect::<Vec<_>>(),
            &psk_ids_with_psks,
            encryption_key,
            nonce,
            user_id,
        ));
        let header =
            HDF::new(message_types::KEYLOAD, new_cursor, identifier.clone(), &topic).with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("send keyload", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if !self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("keyload", message_address));
        }

        let send_response = self
            .transport
            .send_message(message_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send keyload message", e))?;

        // If message has been sent successfully, commit message to stores
        for subscriber in subscribers {
            if self.should_store_cursor(&topic, subscriber) {
                self.state
                    .cursor_store
                    .insert_cursor(&topic, subscriber.into(), INIT_MESSAGE_NUM);
            }
        }
        self.state
            .cursor_store
            .insert_cursor(&topic, Permissioned::Admin(identifier), new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        // Update Branch Links
        self.set_latest_link(topic, message_address.relative());
        Ok(SendResponse::new(message_address, send_response))
    }

    /// Create and send a new Keyload message for all participants, updating the specified branch to
    /// grant all known subscribers read permissions.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    pub async fn send_keyload_for_all<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic> + Clone,
    {
        let topic = topic.into();
        let permission = self.permission(&topic).ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole(
                "Admin",
                permission.identifier().clone(),
                "send a keyload",
            ));
        }
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| {
                if s == permission.identifier() {
                    Permissioned::Admin(s.clone())
                } else {
                    Permissioned::Read(s.clone())
                }
            })
            .collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers.iter().map(Permissioned::as_ref),
            psks,
        )
        .await
    }

    /// Create and send a new Keyload message for all participants, updating the specified branch to
    /// grant all known subscribers read and write permissions.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch the permissions will be updated for.
    pub async fn send_keyload_for_all_rw<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic> + Clone,
    {
        let topic = topic.into();
        let permission = self.permission(&topic).ok_or(Error::NoCursor(topic.clone()))?;
        if !permission.is_admin() {
            return Err(Error::WrongRole(
                "Admin",
                permission.identifier().clone(),
                "send a keyload",
            ));
        }
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| {
                if s == permission.identifier() {
                    Permissioned::Admin(s.clone())
                } else {
                    Permissioned::ReadWrite(s.clone(), PermissionDuration::Perpetual)
                }
            })
            .collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers.iter().map(Permissioned::as_ref),
            psks,
        )
        .await
    }

    /// Create a new [`MessageBuilder`] instance.
    pub fn message<P: Default>(&mut self) -> MessageBuilder<P, T> {
        MessageBuilder::new(self)
    }

    /// Create and send a new Signed Packet message to the specified branch. The message will
    /// contain a masked and an unmasked payload. The message will be signed by the [`User`]
    /// [`Identity`] keys.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to send the message to.
    /// * `public_payload`: The unmasked payload of the message.
    /// * `masked_payload`: The masked payload of the message.
    pub async fn send_signed_packet<P, M, Top>(
        &mut self,
        topic: Top,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
        Top: Into<Topic>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before sending a signed packet, the stream must be created",
        ))?;
        let user_id = self.identity().ok_or(Error::NoIdentity("send signed packet"))?;
        let identifier = user_id.identifier().clone();
        // Check Topic
        let topic = topic.into();
        // Check Permission
        let permission = self
            .state
            .cursor_store
            .get_permission(&topic, &identifier)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if permission.is_readonly() {
            return Err(Error::WrongRole(
                "ReadWrite",
                permission.identifier().clone(),
                "send a signed packet",
            ));
        }
        // Link message to latest message in branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| Error::TopicNotFound(topic.clone()))?;
        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;

        let content = PCF::new_final_frame().with_content(signed_packet::Wrap::new(
            &mut linked_msg_spongos,
            &(*user_id),
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(message_types::SIGNED_PACKET, new_cursor, identifier.clone(), &topic)
            .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("send signed packet", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if !self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("signed packet", message_address));
        }
        let send_response = self
            .transport
            .send_message(message_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send signed packet", e))?;

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, permission.clone(), new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        // Update Branch Links
        self.set_latest_link(topic, message_address.relative());
        Ok(SendResponse::new(message_address, send_response))
    }

    /// Create and send a new Tagged Packet message to the specified branch. The message will
    /// contain a masked and an unmasked payload.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch to send the message to.
    /// * `public_payload`: The unmasked payload of the message.
    /// * `masked_payload`: The masked payload of the message.
    pub async fn send_tagged_packet<P, M, Top>(
        &mut self,
        topic: Top,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
        Top: Into<Topic>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or(Error::Setup(
            "before sending a tagged packet, the stream must be created",
        ))?;
        let user_id = self.identity().ok_or(Error::NoIdentity("send tagged packet"))?;
        let identifier = user_id.identifier().clone();
        // Check Topic
        let topic = topic.into();
        // Check Permission
        let permission = self
            .state
            .cursor_store
            .get_permission(&topic, &identifier)
            .ok_or(Error::NoCursor(topic.clone()))?;
        if permission.is_readonly() {
            return Err(Error::WrongRole(
                "ReadWrite",
                permission.identifier().clone(),
                "send a tagged packet",
            ));
        }
        // Link message to latest message in branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| Error::TopicNotFound(topic.clone()))?;

        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or(Error::MessageMissing(link_to, "spongos store"))?;
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(message_types::TAGGED_PACKET, new_cursor, identifier.clone(), &topic)
            .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content)
            .wrap()
            .await
            .map_err(|e| Error::Wrapped("send tagged packet", e))?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        if !self.transport.recv_message(message_address).await.is_err() {
            return Err(Error::AddressUsed("tagged packet", message_address));
        }
        let send_response = self
            .transport
            .send_message(message_address, transport_msg)
            .await
            .map_err(|e| Error::Transport(stream_address, "send tagged packet", e))?;

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, permission.clone(), new_cursor);
        self.store_spongos(rel_address, spongos, link_to);
        // Update Branch Links
        self.set_latest_link(topic, rel_address);
        Ok(SendResponse::new(message_address, send_response))
    }
}

#[async_trait(?Send)]
impl ContentSizeof<State> for sizeof::Context {
    async fn sizeof(&mut self, user_state: &State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        // Only keep topics that exist in cursor store, any others serve no purpose
        let topics = user_state
            .topics
            .iter()
            .filter(|t| user_state.cursor_store.get_latest_link(t).is_some());
        let amount_topics = topics.clone().count();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let latest_link = user_state
                .cursor_store
                .get_latest_link(topic)
                .ok_or(SpongosError::InvalidAction(
                    "calculate sizeof for topic latest link",
                    topic.to_string(),
                    "No Cursor".to_owned(),
                ))?;
            self.mask(&latest_link)?;

            let cursors: Vec<(&Permissioned<Identifier>, &usize)> = user_state
                .cursor_store
                .cursors_by_topic(topic)
                .ok_or(SpongosError::InvalidAction(
                    "get cursor for topic",
                    topic.to_string(),
                    "No Cursor".to_owned(),
                ))?
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(*cursor))?;
            }
        }

        let subs = &user_state.subscribers;
        let amount_subs = subs.len();
        self.mask(Size::new(amount_subs))?;
        for subscriber in subs {
            self.mask(subscriber)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        let lean = if user_state.lean { 1 } else { 0 };
        self.mask(Uint8::new(lean))?;

        self.commit()?.squeeze(Mac::new(32))
    }
}

#[async_trait(?Send)]
impl<'a> ContentWrap<State> for wrap::Context<&'a mut [u8]> {
    async fn wrap(&mut self, user_state: &mut State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        // Only keep topics that exist in cursor store, any others serve no purpose
        let topics = user_state
            .topics
            .iter()
            .filter(|t| user_state.cursor_store.get_latest_link(t).is_some());
        let amount_topics = topics.clone().count();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let latest_link = user_state
                .cursor_store
                .get_latest_link(topic)
                .ok_or(SpongosError::InvalidAction(
                    "get latest link topic for wrap",
                    topic.to_string(),
                    "No latest link".to_owned(),
                ))?;
            self.mask(&latest_link)?;

            let cursors: Vec<(&Permissioned<Identifier>, &usize)> = user_state
                .cursor_store
                .cursors_by_topic(topic)
                .ok_or(SpongosError::InvalidAction(
                    "get cursor for topic",
                    topic.to_string(),
                    "No cursor found".to_owned(),
                ))?
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(*cursor))?;
            }
        }

        let subs = &user_state.subscribers;
        let amount_subs = subs.len();
        self.mask(Size::new(amount_subs))?;
        for subscriber in subs {
            self.mask(subscriber)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        let lean = if user_state.lean { 1 } else { 0 };
        self.mask(Uint8::new(lean))?;

        self.commit()?.squeeze(Mac::new(32))
    }
}

#[async_trait(?Send)]
impl<'a> ContentUnwrap<State> for unwrap::Context<&'a [u8]> {
    async fn unwrap(&mut self, user_state: &mut State) -> SpongosResult<&mut Self> {
        self.mask(Maybe::new(&mut user_state.user_id))?
            .mask(Maybe::new(&mut user_state.stream_address))?
            .mask(Maybe::new(&mut user_state.author_identifier))?
            .mask(&mut user_state.base_branch)?;

        let mut amount_spongos = Size::default();
        self.mask(&mut amount_spongos)?;
        for _ in 0..amount_spongos.inner() {
            let mut address = MsgId::default();
            let mut spongos = Spongos::default();
            self.mask(&mut address)?.mask(&mut spongos)?;
            user_state.spongos_store.insert(address, spongos);
        }

        let mut amount_topics = Size::default();
        self.mask(&mut amount_topics)?;

        for _ in 0..amount_topics.inner() {
            let mut topic = Topic::default();
            self.mask(&mut topic)?;
            let mut latest_link = MsgId::default();
            self.mask(&mut latest_link)?;

            user_state.topics.insert(topic.clone());
            user_state.cursor_store.set_latest_link(topic.clone(), latest_link);

            let mut amount_cursors = Size::default();
            self.mask(&mut amount_cursors)?;
            for _ in 0..amount_cursors.inner() {
                let mut subscriber = Permissioned::default();
                let mut cursor = Size::default();
                self.mask(&mut subscriber)?.mask(&mut cursor)?;
                user_state
                    .cursor_store
                    .insert_cursor(&topic, subscriber, cursor.inner());
            }
        }

        let mut amount_subs = Size::default();
        self.mask(&mut amount_subs)?;
        for _ in 0..amount_subs.inner() {
            let mut subscriber = Identifier::default();
            self.mask(&mut subscriber)?;
            user_state.subscribers.insert(subscriber);
        }

        let mut amount_psks = Size::default();
        self.mask(&mut amount_psks)?;
        for _ in 0..amount_psks.inner() {
            let mut pskid = PskId::default();
            let mut psk = Psk::default();
            self.mask(&mut pskid)?.mask(&mut psk)?;
            user_state.psk_store.insert(pskid, psk);
        }

        let mut lean = Uint8::new(0);
        self.mask(&mut lean)?;
        user_state.lean = lean.inner() == 1;

        self.commit()?.squeeze(Mac::new(32))
    }
}

impl<T> Debug for User<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FormatResult {
        write!(
            f,
            "\n* identifier: <{:?}>\n* topic: {}\n{:?}\n* PSKs: \n{}\n* messages:\n{}\n* lean: {}\n",
            self.identifier(),
            self.base_branch(),
            self.state.cursor_store,
            self.state
                .psk_store
                .keys()
                .map(|pskid| format!("\t<{:?}>\n", pskid))
                .collect::<String>(),
            self.state
                .spongos_store
                .keys()
                .map(|key| format!("\t<{}>\n", key))
                .collect::<String>(),
            self.state.lean
        )
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> PartialEq for User<T> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> Eq for User<T> {}
