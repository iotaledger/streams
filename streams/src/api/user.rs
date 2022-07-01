// Rust
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt::{Debug, Formatter, Result as FormatResult};

// 3rd-party
use anyhow::{anyhow, bail, ensure, Result};
use async_trait::async_trait;
use futures::{future, TryStreamExt};
use hashbrown::HashMap;
use rand::{rngs::StdRng, Rng, SeedableRng};

// IOTA
use crypto::keys::x25519;

// Streams
use lets::{
    address::{Address, AppAddr, MsgId},
    id::{Identifier, Identity, PermissionDuration, Permissioned, Psk, PskId},
    message::{
        ContentSizeof, ContentUnwrap, ContentWrap, Message as LetsMessage, PreparsedMessage, Topic, TransportMessage,
        HDF, PCF,
    },
    transport::Transport,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask, Squeeze},
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size},
    },
    KeccakF1600, Spongos, SpongosRng,
};

// Local
use crate::{
    api::{
        cursor_store::{CursorStore, InnerCursorStore},
        message::Message,
        messages::Messages,
        send_response::SendResponse,
        user_builder::UserBuilder,
    },
    message::{announcement, keyload, message_types, signed_packet, subscription, tagged_packet, unsubscription},
};

const ANN_MESSAGE_NUM: usize = 0; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: usize = 0; // Subscription is always the first message of subscribers
const INIT_MESSAGE_NUM: usize = 1; // First non-reserved message number

#[derive(PartialEq, Eq, Default)]
struct State {
    /// Users' Identity information, contains keys and logic for signing and verification
    user_id: Option<Identity>,

    /// Address of the stream announcement message
    ///
    /// None if channel is not created or user is not subscribed.
    stream_address: Option<Address>,

    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no) mapped
    /// by branch topic Vec.
    cursor_store: CursorStore,

    /// Mapping of trusted pre shared keys and identifiers
    psk_store: HashMap<PskId, Psk>,

    /// Mapping of exchange keys and identifiers
    exchange_keys: HashMap<Identifier, x25519::PublicKey>,

    spongos_store: HashMap<MsgId, Spongos>,

    base_branch: Topic,
}

pub struct User<T> {
    transport: T,

    state: State,
}

impl User<()> {
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T> User<T> {
    pub(crate) fn new<Psks>(user_id: Option<Identity>, psks: Psks, transport: T) -> Self
    where
        Psks: IntoIterator<Item = (PskId, Psk)>,
    {
        let mut psk_store = HashMap::new();
        let mut exchange_keys = HashMap::new();

        // Store any pre shared keys
        psks.into_iter().for_each(|(pskid, psk)| {
            psk_store.insert(pskid, psk);
        });

        if let Some(id) = user_id.as_ref() {
            exchange_keys.insert(id.to_identifier(), id._ke_sk().public_key());
        }

        Self {
            transport,
            state: State {
                user_id,
                cursor_store: CursorStore::new(),
                psk_store,
                exchange_keys,
                spongos_store: Default::default(),
                stream_address: None,
                author_identifier: None,
                base_branch: Default::default(),
            },
        }
    }

    /// User's identifier
    pub fn identifier(&self) -> Option<Identifier> {
        self.identity().ok().map(|id| id.to_identifier())
    }

    /// User Identity
    fn identity(&self) -> Result<&Identity> {
        self.state
            .user_id
            .as_ref()
            .ok_or_else(|| anyhow!("User does not have a stored identity"))
    }

    /// User's cursor
    fn cursor(&self, topic: &Topic) -> Option<usize> {
        self.identifier()
            .and_then(|id| self.state.cursor_store.get_cursor(topic, &id))
    }

    fn next_cursor(&self, topic: &Topic) -> Result<usize> {
        self.cursor(topic)
            .map(|c| c + 1)
            .ok_or_else(|| anyhow!("User is not a publisher"))
    }

    pub(crate) fn base_branch(&self) -> &Topic {
        &self.state.base_branch
    }

    pub(crate) fn stream_address(&self) -> Option<Address> {
        self.state.stream_address
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn topics(&self) -> impl Iterator<Item = &Topic> + ExactSizeIterator {
        self.state.cursor_store.topics()
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (&Topic, &Identifier, usize)> + '_ {
        self.state.cursor_store.cursors()
    }

    pub fn subscribers(&self) -> impl Iterator<Item = &Identifier> + Clone + '_ {
        self.state.exchange_keys.keys()
    }

    fn should_store_cursor(&self, topic: &Topic, subscriber: Permissioned<&Identifier>) -> bool {
        let no_tracked_cursor = !self
            .state
            .cursor_store
            .is_cursor_tracked(topic, subscriber.identifier());
        !subscriber.is_readonly() && no_tracked_cursor
    }

    pub fn add_subscriber(&mut self, subscriber: Identifier) -> bool {
        let ke_pk = subscriber
            ._ke_pk()
            .expect("subscriber must have an identifier from which an x25519 public key can be derived");
        self.state.exchange_keys.insert(subscriber, ke_pk).is_none()
    }

    pub fn remove_subscriber(&mut self, id: &Identifier) -> bool {
        self.state.cursor_store.remove(id) | self.state.exchange_keys.remove(id).is_some()
    }

    pub fn add_psk(&mut self, psk: Psk) -> bool {
        self.state.psk_store.insert(psk.to_pskid(), psk).is_none()
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.state.psk_store.remove(&pskid).is_some()
    }

    /// Sets the anchor message link for a specified branch. If the branch does not exist, it is
    /// created
    fn set_anchor(&mut self, topic: &Topic, anchor: MsgId) -> Option<InnerCursorStore> {
        self.state.cursor_store.set_anchor(topic, anchor)
    }

    /// Sets the latest message link for a specified branch. If the branch does not exist, it is
    /// created
    fn set_latest_link(&mut self, topic: &Topic, latest_link: MsgId) -> Option<InnerCursorStore> {
        self.state.cursor_store.set_latest_link(topic, latest_link)
    }

    fn get_anchor(&self, topic: &Topic) -> Option<MsgId> {
        self.state.cursor_store.get_anchor(topic)
    }

    fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.state.cursor_store.get_latest_link(topic)
    }

    pub(crate) async fn handle_message(&mut self, address: Address, msg: TransportMessage) -> Result<Message> {
        let preparsed = msg.parse_header().await?;
        match preparsed.header().message_type() {
            message_types::ANNOUNCEMENT => self.handle_announcement(address, preparsed).await,
            message_types::SUBSCRIPTION => self.handle_subscription(address, preparsed).await,
            message_types::UNSUBSCRIPTION => self.handle_unsubscription(address, preparsed).await,
            message_types::KEYLOAD => self.handle_keyload(address, preparsed).await,
            message_types::SIGNED_PACKET => self.handle_signed_packet(address, preparsed).await,
            message_types::TAGGED_PACKET => self.handle_tagged_packet(address, preparsed).await,
            unknown => Err(anyhow!("unexpected message type {}", unknown)),
        }
    }

    /// Bind Subscriber to the channel announced
    /// in the message.
    async fn handle_announcement(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Check Topic
        let topic = preparsed.header().topic();
        let publisher = preparsed.header().publisher();
        let is_base_branch = self.state.stream_address.is_none();

        // Insert new branch into store
        self.state.cursor_store.new_branch(topic.clone());

        // If the topic of the announcement is not base branch the author cursor needs to be iterated
        // on the base branch
        if !is_base_branch {
            self.state.cursor_store.insert_cursor(
                &self.state.base_branch,
                publisher.clone(),
                preparsed.header().sequence(),
            );
        }

        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(topic, publisher.clone(), INIT_MESSAGE_NUM);

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed.unwrap(announcement).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        let topic = message.header().topic();
        let author_id = message.payload().content().author_id();
        let author_ke_pk = message.payload().content().author_ke_pk();

        // Update branch links
        self.set_anchor(topic, address.relative());
        self.set_latest_link(topic, address.relative());
        self.state.author_identifier = Some(author_id.clone());

        if is_base_branch {
            self.state.exchange_keys.insert(author_id.clone(), author_ke_pk.clone());
            self.state.base_branch = topic.clone();
            self.state.stream_address = Some(address);
        }

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_subscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as cursor is only tracked for subscribers with write permissions

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("subscription messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_ke_sk = &self.identity()?._ke_sk();
        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, _spongos) = preparsed.unwrap(subscription).await?;

        // Store spongos
        // Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers

        // Store message content into stores
        let subscriber_identifier = message.payload().content().subscriber_identifier();
        let subscriber_ke_pk = message.payload().content().subscriber_ke_pk();
        self.state
            .exchange_keys
            .insert(subscriber_identifier.clone(), subscriber_ke_pk);

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_unsubscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as user is unsubscribing

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                *spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(unsubscription).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        self.remove_subscriber(message.payload().content().subscriber_identifier());

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_keyload(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state.cursor_store.insert_cursor(
            preparsed.header().topic(),
            preparsed.header().publisher().clone(),
            preparsed.header().sequence(),
        );

        // Unwrap message
        let author_identifier = self.state.author_identifier.as_ref().ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        self.stream_address()
            .ok_or_else(|| anyhow!("before handling a keyload one must have received a stream announcement first"))?;
        let prev_msg = preparsed
            .header()
            .linked_msg_address()
            .ok_or_else(|| anyhow!("a keyload must have a previously linked message"))?;
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(&prev_msg)
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let keyload = keyload::Unwrap::new(
            &mut announcement_spongos,
            self.state.user_id.as_ref(),
            author_identifier,
            &self.state.psk_store,
        );
        let (message, spongos) = preparsed.unwrap(keyload).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        for subscriber in message.payload().content().subscribers() {
            if self.should_store_cursor(message.header().topic(), subscriber.as_ref()) {
                self.state.cursor_store.insert_cursor(
                    message.header().topic(),
                    subscriber.identifier().clone(),
                    INIT_MESSAGE_NUM,
                );
            }
        }

        // Have to make message before setting branch links due to immutable borrow in keyload::unwrap
        let final_message = Message::from_lets_message(address, message);
        // Update branch links
        self.set_latest_link(&final_message.header().topic, address.relative());
        Ok(final_message)
    }

    async fn handle_signed_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state.cursor_store.insert_cursor(
            preparsed.header().topic(),
            preparsed.header().publisher().clone(),
            preparsed.header().sequence(),
        );

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let signed_packet = signed_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(signed_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        self.set_latest_link(message.header().topic(), address.relative());
        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_tagged_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state.cursor_store.insert_cursor(
            preparsed.header().topic(),
            preparsed.header().publisher().clone(),
            preparsed.header().sequence(),
        );

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(tagged_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        self.set_latest_link(message.header().topic(), address.relative());

        Ok(Message::from_lets_message(address, message))
    }

    pub async fn backup<P>(&mut self, pwd: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.state).await?;
        let buf_size = ctx.finalize() + 32; // State + Mac Size

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))?
            .commit()?
            .squeeze(&Mac::new(32))?;
        ctx.wrap(&mut self.state).await?;
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );

        Ok(buf)
    }

    pub async fn restore<B, P>(backup: B, pwd: P, transport: T) -> Result<Self>
    where
        P: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut ctx = unwrap::Context::new(backup.as_ref());
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))?
            .commit()?
            .squeeze(&Mac::new(32))?;
        let mut state = State::default();
        ctx.unwrap(&mut state).await?;
        Ok(User { transport, state })
    }
}

impl<T> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage>,
{
    pub async fn receive_message(&mut self, address: Address) -> Result<Message>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage>,
    {
        let msg = self.transport.recv_message(address).await?;
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
        self.messages().try_fold(0, |n, _| future::ok(n + 1)).await
    }

    /// Iteratively fetches all the pending messages from the transport
    ///
    /// Return a vector with all the messages collected. This is a convenience
    /// method around the [`Messages`] stream. Check out its docs for more
    /// advanced usages.
    pub async fn fetch_next_messages(&mut self) -> Result<Vec<Message>> {
        self.messages().try_collect().await
    }
}

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR>,
{
    /// Prepare channel Announcement message.
    pub async fn create_stream<Top: Into<Topic>>(&mut self, topic: Top) -> Result<SendResponse<TSR>> {
        // Check conditions
        if let Some(appaddr) = self.stream_address() {
            bail!(
                "Cannot create a channel, user is already registered to channel {}",
                appaddr
            );
        }
        // Confirm user has identity
        let identifier = self.identity()?.to_identifier();
        // Convert topic
        let topic = topic.into();
        // Generate stream address
        let stream_base_address = AppAddr::gen(&identifier, &topic);
        let stream_rel_address = MsgId::gen(stream_base_address, &identifier, &topic, INIT_MESSAGE_NUM);
        let stream_address = Address::new(stream_base_address, stream_rel_address);

        // Commit Author Identifier and Stream Address to store
        self.state.stream_address = Some(stream_address);
        self.state.author_identifier = Some(identifier);
        self.state.base_branch = topic.clone();

        // Insert the base branch into store
        self.state.cursor_store.new_branch(topic.clone());

        // Create Base Branch
        self.new_branch(topic).await
    }

    /// Prepare new branch Announcement message
    pub async fn new_branch<Top: Into<Topic>>(&mut self, topic: Top) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before starting a new branch, the stream must be created"))?;
        // Confirm user has identity
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Check Topic
        let topic: Topic = topic.into();
        let base_branch = &self.state.base_branch;
        let is_base_branch = topic.eq(base_branch);

        // Update own's cursor
        let (user_cursor, address, topic) = if is_base_branch {
            (ANN_MESSAGE_NUM, stream_address, base_branch)
        } else {
            let cursor = self
                .next_cursor(base_branch)
                .map_err(|_| anyhow!("No cursor found in base branch"))?;
            let msgid = MsgId::gen(stream_address.base(), &identifier, &base_branch, cursor);
            let address = Address::new(stream_address.base(), msgid);
            (cursor, address, &topic)
        };

        // Prepare HDF and PCF
        let header = HDF::new(
            message_types::ANNOUNCEMENT,
            user_cursor,
            identifier.clone(),
            topic.clone(),
        )?;
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(user_id));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        ensure!(
            self.transport.recv_message(address).await.is_err(),
            anyhow!("stream with address '{}' already exists", address)
        );
        let send_response = self.transport.send_message(address, transport_msg).await?;

        // If the branch has not been created yet, create it
        if !is_base_branch {
            self.state.cursor_store.new_branch(topic.clone());
            self.state
                .cursor_store
                .insert_cursor(&base_branch, identifier.clone(), self.next_cursor(&base_branch)?);
        }

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, identifier.clone(), INIT_MESSAGE_NUM);
        self.state.spongos_store.insert(address.relative(), spongos);

        // Update branch links
        self.state.cursor_store.set_anchor(topic, address.relative());
        self.state.cursor_store.set_latest_link(topic, address.relative());
        Ok(SendResponse::new(address, send_response))
    }

    /// Prepare Subscribe message.
    pub async fn subscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before subscribing one must receive the announcement of a stream first"))?;
        // Confirm user has identity
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Get base branch topic
        let base_branch = &self.state.base_branch;
        // Link message to channel announcement
        let link_to = self
            .get_anchor(base_branch)
            .ok_or_else(|| anyhow!("No anchor found in branch <{}>", base_branch))?;

        let rel_address = MsgId::gen(stream_address.base(), &identifier, &base_branch, SUB_MESSAGE_NUM);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .state
            .author_identifier
            .as_ref()
            .and_then(|author_id| self.state.exchange_keys.get(author_id))
            .expect("a user that already have an stream address must know the author identifier");
        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            user_id,
            author_ke_pk,
        ));
        let header = HDF::new(
            message_types::SUBSCRIPTION,
            SUB_MESSAGE_NUM,
            identifier.clone(),
            base_branch.clone(),
        )?
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, _spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        // - Subscription messages are not stored in the cursor store
        // - Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn unsubscribe(&mut self) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a subscription one must receive the announcement of a stream first")
        })?;
        // Confirm user has identity
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Get base branch topic
        let base_branch = &self.state.base_branch;
        // Link message to channel announcement
        let link_to = self
            .get_anchor(base_branch)
            .ok_or_else(|| anyhow!("No anchor found in branch <{}>", base_branch))?;

        // Update own's cursor
        let new_cursor = self.next_cursor(&base_branch)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &base_branch, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, user_id));
        let header = HDF::new(
            message_types::UNSUBSCRIPTION,
            new_cursor,
            identifier.clone(),
            base_branch.clone(),
        )?
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&base_branch, identifier, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload<'a, Subscribers, Psks, Top>(
        &mut self,
        topic: Top,
        subscribers: Subscribers,
        psk_ids: Psks,
    ) -> Result<SendResponse<TSR>>
    where
        Subscribers: IntoIterator<Item = Permissioned<&'a Identifier>>,
        Top: Into<Topic>,
        Psks: IntoIterator<Item = PskId>,
    {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before sending a keyload one must create a stream first"))?;
        // Confirm user has identity
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Check Topic
        let topic = topic.into();
        // Link message to anchor in branch
        let link_to = self
            .get_anchor(&topic)
            .ok_or_else(|| anyhow!("No anchor found in branch <{}>", topic))?;
        // Update own's cursor
        let new_cursor = self.next_cursor(&topic)?;
        let rel_address = MsgId::gen(stream_address.base(), &identifier, &topic, new_cursor);

        // Prepare HDF and PCF
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let exchange_keys = &self.state.exchange_keys; // partial borrow to avoid borrowing the whole self within the closure
        let subscribers_with_keys = subscribers
            .into_iter()
            .map(|subscriber| {
                Ok((
                    subscriber,
                    exchange_keys
                        .get(subscriber.identifier())
                        .ok_or_else(|| anyhow!("unknown subscriber '{}'", subscriber.identifier()))?,
                ))
            })
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let psk_ids_with_psks = psk_ids
            .into_iter()
            .map(|pskid| {
                Ok((
                    pskid,
                    self.state
                        .psk_store
                        .get(&pskid)
                        .ok_or_else(|| anyhow!("unkown psk '{:?}'", pskid))?,
                ))
            })
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut linked_msg_spongos,
            subscribers_with_keys.iter().copied(),
            &psk_ids_with_psks,
            encryption_key,
            nonce,
            user_id,
        ));
        let header = HDF::new(message_types::KEYLOAD, new_cursor, identifier.clone(), topic.clone())?
            .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        for (subscriber, _) in subscribers_with_keys {
            if self.should_store_cursor(&topic, subscriber) {
                self.state
                    .cursor_store
                    .insert_cursor(&topic, (*subscriber.identifier()).clone(), INIT_MESSAGE_NUM);
            }
        }
        self.state.cursor_store.insert_cursor(&topic, identifier, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        // Update Branch Links
        self.set_latest_link(&topic, message_address.relative());
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload_for_all<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic>,
    {
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> =
            self.subscribers().map(|s| Permissioned::Read(s.clone())).collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers.iter().map(Permissioned::as_ref),
            psks,
        )
        .await
    }

    pub async fn send_keyload_for_all_rw<Top>(&mut self, topic: Top) -> Result<SendResponse<TSR>>
    where
        Top: Into<Topic>,
    {
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| Permissioned::ReadWrite(s.clone(), PermissionDuration::Perpetual))
            .collect();
        self.send_keyload(
            topic,
            // Alas, must collect to release the &self immutable borrow
            subscribers.iter().map(Permissioned::as_ref),
            psks,
        )
        .await
    }

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
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a signed packet one must receive the announcement of a stream first")
        })?;
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Check Topic
        let topic = topic.into();
        // Link message to latest message in branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| anyhow!("No latest link found in branch <{}>", topic))?;
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
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(signed_packet::Wrap::new(
            &mut linked_msg_spongos,
            self.identity()?,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(
            message_types::SIGNED_PACKET,
            new_cursor,
            identifier.clone(),
            topic.clone(),
        )?
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state
            .cursor_store
            .insert_cursor(&topic, identifier.clone(), new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        // Update Branch Links
        self.set_latest_link(&topic, message_address.relative());
        Ok(SendResponse::new(message_address, send_response))
    }

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
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a tagged packet one must receive the announcement of a stream first")
        })?;
        let user_id = self.identity()?;
        let identifier = user_id.to_identifier();
        // Check Topic
        let topic = topic.into();
        // Link message to latest message in branch
        let link_to = self
            .get_latest_link(&topic)
            .ok_or_else(|| anyhow!("No latest link found in branch <{}>", topic))?;

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
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(
            message_types::TAGGED_PACKET,
            new_cursor,
            identifier.clone(),
            topic.clone(),
        )?
        .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.cursor_store.insert_cursor(&topic, identifier, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        // Update Branch Links
        self.set_latest_link(&topic, rel_address);
        Ok(SendResponse::new(message_address, send_response))
    }
}

#[async_trait(?Send)]
impl ContentSizeof<State> for sizeof::Context {
    async fn sizeof(&mut self, user_state: &State) -> Result<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let topics = user_state.cursor_store.topics();
        let amount_topics = topics.len();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let anchor = user_state
                .cursor_store
                .get_anchor(topic)
                .ok_or_else(|| anyhow!("No anchor found in branch <{}>", topic))?;
            let latest_link = user_state
                .cursor_store
                .get_latest_link(topic)
                .ok_or_else(|| anyhow!("No latest link found in branch <{}>", topic))?;
            self.mask(&anchor)?.mask(&latest_link)?;

            let cursors: Vec<(&Topic, &Identifier, usize)> = user_state
                .cursor_store
                .cursors()
                .filter(|(t, _, _)| *t == topic)
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (_, subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(cursor))?;
            }
        }

        let keys = &user_state.exchange_keys;
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(subscriber)?.mask(ke_pk)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a> ContentWrap<State> for wrap::Context<&'a mut [u8]> {
    async fn wrap(&mut self, user_state: &mut State) -> Result<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?
            .mask(&user_state.base_branch)?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let topics = user_state.cursor_store.topics();
        let amount_topics = topics.len();
        self.mask(Size::new(amount_topics))?;

        for topic in topics {
            self.mask(topic)?;
            let anchor = user_state
                .cursor_store
                .get_anchor(topic)
                .ok_or_else(|| anyhow!("No anchor found in branch <{}>", topic))?;
            let latest_link = user_state
                .cursor_store
                .get_latest_link(topic)
                .ok_or_else(|| anyhow!("No latest link found in branch <{}>", topic))?;
            self.mask(&anchor)?.mask(&latest_link)?;

            let cursors: Vec<(&Topic, &Identifier, usize)> = user_state
                .cursor_store
                .cursors()
                .filter(|(t, _, _)| *t == topic)
                .collect();
            let amount_cursors = cursors.len();
            self.mask(Size::new(amount_cursors))?;
            for (_, subscriber, cursor) in cursors {
                self.mask(subscriber)?.mask(Size::new(cursor))?;
            }
        }

        let keys = &user_state.exchange_keys;
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(subscriber)?.mask(ke_pk)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }

        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a> ContentUnwrap<State> for unwrap::Context<&'a [u8]> {
    async fn unwrap(&mut self, user_state: &mut State) -> Result<&mut Self> {
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
            let mut anchor = MsgId::default();
            let mut latest_link = MsgId::default();
            self.mask(&mut anchor)?.mask(&mut latest_link)?;

            user_state.cursor_store.set_anchor(&topic, anchor);
            user_state.cursor_store.set_latest_link(&topic, latest_link);

            let mut amount_cursors = Size::default();
            self.mask(&mut amount_cursors)?;
            for _ in 0..amount_cursors.inner() {
                let mut subscriber = Identifier::default();
                let mut cursor = Size::default();
                self.mask(&mut subscriber)?.mask(&mut cursor)?;
                user_state
                    .cursor_store
                    .insert_cursor(&topic, subscriber, cursor.inner());
            }
        }

        let mut amount_keys = Size::default();
        self.mask(&mut amount_keys)?;
        for _ in 0..amount_keys.inner() {
            let mut subscriber = Identifier::default();
            let mut key = x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]);
            self.mask(&mut subscriber)?.mask(&mut key)?;
            user_state.exchange_keys.insert(subscriber, key);
        }

        let mut amount_psks = Size::default();
        self.mask(&mut amount_psks)?;
        for _ in 0..amount_psks.inner() {
            let mut pskid = PskId::default();
            let mut psk = Psk::default();
            self.mask(&mut pskid)?.mask(&mut psk)?;
            user_state.psk_store.insert(pskid, psk);
        }

        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

impl<T> Debug for User<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FormatResult {
        write!(
            f,
            "\n* identifier: <{}>\n* topic: {}\n{:?}\n* PSKs: \n{}\n* messages:\n{}\n",
            self.identifier().unwrap_or_default(),
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
                .collect::<String>()
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
