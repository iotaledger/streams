// Rust
use alloc::{
    boxed::Box,
    format,
    string::String,
    vec::Vec,
};
use core::{
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
    },
    hash::Hash,
};

// 3rd-party
use anyhow::{
    anyhow,
    bail,
    ensure,
    Result,
};
use async_trait::async_trait;
use futures::{
    future,
    TryStreamExt,
};
use hashbrown::HashMap;
use rand::{
    rngs::StdRng,
    Rng,
    SeedableRng,
};

// IOTA
use crypto::keys::x25519;

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Mask,
            Squeeze,
        },
        modifiers::External,
        types::{
            Mac,
            Maybe,
            NBytes,
            Size,
        },
    },
    KeccakF1600,
    Spongos,
    SpongosRng,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
        Permissioned,
        Psk,
        PskId,
    },
    link::{
        Address,
        AddressGenerator,
        Link,
        LinkGenerator,
    },
    message::{
        ContentSizeof,
        ContentUnwrap,
        ContentWrap,
        Message as LetsMessage,
        PreparsedMessage,
        TransportMessage,
        HDF,
        PCF,
    },
    transport::Transport,
};

// Local
use crate::{
    api::{
        key_store::KeyStore,
        message::Message,
        messages::{
            IntoMessages,
            Messages,
        },
        send_response::SendResponse,
        user_builder::UserBuilder,
    },
    message::{
        announcement,
        keyload,
        message_types,
        signed_packet,
        subscription,
        tagged_packet,
        unsubscription,
    },
};

const ANN_MESSAGE_NUM: usize = 1; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: usize = 1; // Subscription is always the first message of subscribers
const INIT_MESSAGE_NUM: usize = 5; // First non-reserved message number

#[derive(PartialEq, Eq)]
struct State<F, A>
where
    A: Link,
    A::Relative: Eq + Hash,
{
    /// Users' Identity information, contains keys and logic for signing and verification
    user_id: Identity,

    /// Address of the stream announcement message
    ///
    /// None if channel is not created or user is not subscribed.
    stream_address: Option<A>,

    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    id_store: KeyStore,

    spongos_store: HashMap<A::Relative, Spongos<F>>,
}

impl<F, A> Default for State<F, A>
where
    A: Link,
    A::Relative: Eq + Hash,
{
    fn default() -> Self {
        Self {
            user_id: Default::default(),
            stream_address: Default::default(),
            author_identifier: Default::default(),
            id_store: Default::default(),
            spongos_store: Default::default(),
        }
    }
}

pub struct User<T, F = KeccakF1600, A = Address, AG = AddressGenerator<KeccakF1600>>
where
    A: Link,
    A::Relative: Eq + Hash,
{
    transport: T,

    /// Address generator.
    address_generator: AG,
    state: State<F, A>,
}

impl User<(), KeccakF1600, Address, AddressGenerator<KeccakF1600>> {
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T, F, A, AG> User<T, F, A, AG>
where
    A: Link,
    A::Relative: Eq + Hash,
    F: PRP + Default,
{
    pub(crate) fn new(user_id: Identity, transport: T) -> Self
    where
        AG: Default,
    {
        let mut id_store = KeyStore::default();
        // If User is using a Psk as their base Identifier, store the Psk
        if let Identity::Psk(psk) = user_id {
            id_store.insert_psk(psk.to_pskid::<F>(), psk);
        } else {
            id_store.insert_key(
                user_id.to_identifier(),
                user_id
                    ._ke_sk()
                    .expect("except PSK, all identities must be able to derive an x25519 key")
                    .public_key(),
            );
        }

        Self {
            transport,
            address_generator: Default::default(),
            state: State {
                user_id,
                id_store,
                spongos_store: Default::default(),
                stream_address: None,
                author_identifier: None,
            },
        }
    }

    /// User's identifier
    pub fn identifier(&self) -> Identifier {
        self.state.user_id.to_identifier()
    }

    /// User's cursor
    fn cursor(&self) -> Option<usize> {
        self.state.id_store.get_cursor(&self.identifier())
    }
    fn next_cursor(&self) -> Result<usize> {
        self.cursor()
            .map(|c| c + 1)
            .ok_or_else(|| anyhow!("User is not a publisher"))
    }

    pub(crate) fn stream_address(&self) -> &Option<A> {
        &self.state.stream_address
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, usize)> + ExactSizeIterator + '_ {
        self.state.id_store.cursors()
    }

    pub fn subscribers(&self) -> impl Iterator<Item = Identifier> + Clone + '_ {
        self.state.id_store.subscribers()
    }

    fn should_store_cursor(&self, subscriber: &Permissioned<Identifier>) -> bool {
        let no_tracked_cursor = !self.state.id_store.is_cursor_tracked(subscriber.identifier());
        let must_track_cursor = !subscriber.identifier().is_psk() && !subscriber.is_readonly();
        must_track_cursor && no_tracked_cursor
    }

    pub fn add_subscriber(&mut self, subscriber: Identifier) -> bool {
        self.state.id_store.insert_key(
            subscriber,
            subscriber
                ._ke_pk()
                .expect("subscriber must have an identifier from which an x25519 public key can be derived"),
        )
    }

    pub fn remove_subscriber(&mut self, id: Identifier) -> bool {
        self.state.id_store.remove(&id)
    }

    pub fn add_psk(&mut self, psk: Psk) -> bool {
        self.state.id_store.insert_psk(psk.to_pskid::<F>(), psk)
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.state.id_store.remove_psk(pskid)
    }

    /// Create a new stream (without announcing it). User now becomes Author.
    pub fn create_stream(&mut self, channel_idx: usize) -> Result<()>
    where
        AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, usize)>
            + LinkGenerator<'static, A::Base, Data = (Identifier, usize)>,
        A: Display,
    {
        // TODO: MERGE WITH ANNOUNCE
        if let Some(appaddr) = self.stream_address() {
            bail!(
                "Cannot create a channel, user is already registered to channel {}",
                appaddr
            );
        }
        let user_identifier = self.identifier();
        let stream_base_address = self.address_generator.gen((user_identifier, channel_idx));
        let stream_rel_address = self
            .address_generator
            .gen((&stream_base_address, user_identifier, INIT_MESSAGE_NUM));
        self.state.stream_address = Some(A::from_parts(stream_base_address, stream_rel_address));
        self.state.author_identifier = Some(self.identifier());

        Ok(())
    }
}

impl<T, F, A, AG, TSR> User<T, F, A, AG>
where
    T: for<'a> Transport<'a, Address = &'a A, Msg = TransportMessage, SendResponse = TSR>,
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Display,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, usize)>,
    F: PRP + Default + Clone,
    for<'a, 'b> wrap::Context<F, &'a mut [u8]>: Absorb<&'b A::Relative>,
    for<'a> sizeof::Context: Absorb<&'a A::Relative>,
{
    /// Prepare Announcement message.
    pub async fn announce(&mut self) -> Result<SendResponse<A, TSR>> {
        // Check conditions
        let stream_address = self
            .state
            .stream_address
            .as_ref()
            .ok_or_else(|| anyhow!("before sending the announcement one must create the stream first"))?;

        // Update own's cursor
        let user_cursor = ANN_MESSAGE_NUM;

        // Prepare HDF and PCF
        let header = HDF::new(message_types::ANNOUNCEMENT, user_cursor, self.identifier())?;
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(&self.state.user_id));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        ensure!(
            self.transport.recv_message(stream_address).await.is_err(),
            anyhow!("stream with address '{}' already exists", stream_address)
        );
        let send_response = self.transport.send_message(stream_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.id_store.insert_cursor(self.identifier(), INIT_MESSAGE_NUM);
        self.state
            .spongos_store
            .insert(stream_address.relative().clone(), spongos);
        Ok(SendResponse::new(stream_address.clone(), send_response))
    }

    /// Prepare Subscribe message.
    pub async fn subscribe(&mut self, link_to: A::Relative) -> Result<SendResponse<A, TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("before subscribing one must receive the announcement of a stream first"))?;

        let user_cursor = SUB_MESSAGE_NUM;
        // Update own's cursor
        let rel_address: A::Relative =
            self.address_generator
                .gen((stream_address.base(), self.identifier(), user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .state
            .author_identifier
            .and_then(|author_id| self.state.id_store.get_key(&author_id))
            .expect("a user that already have an stream address must know the author identifier");
        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            &self.state.user_id,
            author_ke_pk,
        ));
        let header =
            HDF::new(message_types::SUBSCRIPTION, user_cursor, self.identifier())?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, _spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = A::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        // - Subscription messages are not stored in the cursor store
        // - Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn unsubscribe(&mut self, link_to: A::Relative) -> Result<SendResponse<A, TSR>> {
        // Check conditions
        let stream_address = self.stream_address().as_ref().cloned().ok_or_else(|| {
            anyhow!("before sending a subscription one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address: A::Relative =
            self.address_generator
                .gen((stream_address.base(), self.identifier(), new_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content = PCF::new_final_frame()
            .with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, &self.state.user_id));
        let header =
            HDF::new(message_types::UNSUBSCRIPTION, new_cursor, self.identifier())?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = A::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.id_store.insert_cursor(self.identifier(), new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload<'a, Subscribers>(
        &mut self,
        link_to: A::Relative,
        subscribers: Subscribers,
    ) -> Result<SendResponse<A, TSR>>
    where
        Subscribers: IntoIterator<Item = Permissioned<Identifier>> + Clone,
    {
        // Check conditions
        let stream_address = self
            .stream_address()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("before sending a keyload one must create a stream first"))?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address: A::Relative =
            self.address_generator
                .gen((stream_address.base(), self.identifier(), new_cursor));

        // Prepare HDF and PCF
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(stream_address.relative())
            .expect("a subscriber that has received an stream announcement must keep its spongos in store")
            // Spongos must be cloned because wrapping mutates it
            .clone();

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let subscribers_with_keys = subscribers
            .clone()
            .into_iter()
            .map(|subscriber| {
                Ok((
                    subscriber,
                    self.state
                        .id_store
                        .get_exchange_key(subscriber.identifier())
                        .ok_or_else(|| anyhow!("unknown subscriber '{}'", subscriber.identifier()))?,
                ))
            })
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut announcement_spongos,
            &subscribers_with_keys,
            encryption_key,
            nonce,
            &self.state.user_id,
        ));
        let header = HDF::new(message_types::KEYLOAD, new_cursor, self.identifier())?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = A::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        for subscriber in subscribers {
            if self.should_store_cursor(&subscriber) {
                self.state
                    .id_store
                    .insert_cursor(*subscriber.identifier(), INIT_MESSAGE_NUM);
            }
        }
        self.state.id_store.insert_cursor(self.identifier(), new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload_for_all(&mut self, link_to: A::Relative) -> Result<SendResponse<A, TSR>> {
        self.send_keyload(
            link_to,
            // Alas, must collect to release the &self immutable borrow
            self.subscribers().map(Permissioned::Read).collect::<Vec<_>>(),
        )
        .await
    }

    pub async fn send_signed_packet<P, M>(
        &mut self,
        link_to: A::Relative,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<A, TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        // Check conditions
        let stream_address = self.stream_address().as_ref().cloned().ok_or_else(|| {
            anyhow!("before sending a signed packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address: A::Relative =
            self.address_generator
                .gen((stream_address.base(), self.identifier(), new_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content = PCF::new_final_frame().with_content(signed_packet::Wrap::new(
            &mut linked_msg_spongos,
            &self.state.user_id,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header =
            HDF::new(message_types::SIGNED_PACKET, new_cursor, self.identifier())?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = A::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.id_store.insert_cursor(self.identifier(), new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_tagged_packet<P, M>(
        &mut self,
        link_to: A::Relative,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<A, TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        // Check conditions
        let stream_address = self.stream_address().as_ref().cloned().ok_or_else(|| {
            anyhow!("before sending a tagged packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address: A::Relative =
            self.address_generator
                .gen((stream_address.base(), self.identifier(), new_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header =
            HDF::new(message_types::TAGGED_PACKET, new_cursor, self.identifier())?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = A::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.id_store.insert_cursor(self.identifier(), new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<T, F, A, AG> User<T, F, A, AG>
where
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Default,
    A::Base: Clone,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, usize)> + Default,
    F: PRP + Default + Clone,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
{
    pub async fn receive_message(&mut self, address: A) -> Result<Message<A>>
    where
        T: for<'a> Transport<'a, Address = &'a A, Msg = TransportMessage>,
    {
        let msg = self.transport.recv_message(&address).await?;
        self.handle_message(address, msg).await
    }

    pub(crate) async fn handle_message(&mut self, address: A, msg: TransportMessage) -> Result<Message<A>> {
        let preparsed = msg.parse_header::<F, A::Relative>().await?;
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
    async fn handle_announcement<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        if let Some(stream_address) = self.stream_address() {
            bail!("user is already connected to the stream {}", stream_address);
        }

        // From the point of view of cursor tracking, the message exists, regardless of the validity or accessibility to
        // its content. Therefore we must update the cursor of the publisher before handling the message
        self.state
            .id_store
            .insert_cursor(preparsed.header().publisher(), INIT_MESSAGE_NUM);

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed.unwrap(announcement).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        let author_id = message.payload().content().author_id();
        let author_ke_pk = message.payload().content().author_ke_pk();
        self.state.id_store.insert_key(author_id, author_ke_pk);
        self.state.stream_address = Some(address.clone());
        self.state.author_identifier = Some(author_id);

        Ok(Message::from_lets_message(address, message))
    }
    async fn handle_subscription<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Cursor is not stored, as cursor is only tracked for subscribers with write permissions

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("subscription messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_ke_sk = &self.state.user_id._ke_sk().ok_or_else(|| {
            anyhow!("reader of a stream must have an identity from which an x25519 secret-key can be derived")
        })?;
        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, _spongos) = preparsed.unwrap(subscription).await?;

        // Store spongos
        // Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers

        // Store message content into stores
        let subscriber_identifier = message.payload().content().subscriber_identifier();
        let subscriber_ke_pk = message.payload().content().subscriber_ke_pk();
        self.state.id_store.insert_key(subscriber_identifier, subscriber_ke_pk);

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_unsubscription<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Cursor is not stored, as user is unsubscribing

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(unsubscription).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        self.remove_subscriber(message.payload().content().subscriber_identifier());

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_keyload<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or accessibility to
        // its content. Therefore we must update the cursor of the publisher before handling the message
        self.state
            .id_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let author_identifier = self.state.author_identifier.ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        let stream_address = self
            .stream_address()
            .as_ref()
            .ok_or_else(|| anyhow!("before handling a keyload one must have received a stream announcement first"))?;
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(stream_address.relative())
            .expect("a subscriber that has received an stream announcement must keep its spongos in store")
            // Spongos must be cloned because wrapping mutates it
            .clone();

        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let user_ke_sk = self.state.user_id._ke();
        let keyload = keyload::Unwrap::new(
            &mut announcement_spongos,
            &self.state.user_id,
            &user_ke_sk,
            author_identifier,
        );
        let (message, spongos) = preparsed.unwrap(keyload).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        for subscriber in message.payload().content().subscribers() {
            if self.should_store_cursor(subscriber) {
                self.state
                    .id_store
                    .insert_cursor(*subscriber.identifier(), INIT_MESSAGE_NUM);
            }
        }

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_signed_packet<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or accessibility to
        // its content. Therefore we must update the cursor of the publisher before handling the message
        self.state
            .id_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let signed_packet = signed_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(signed_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_tagged_packet<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or accessibility to
        // its content. Therefore we must update the cursor of the publisher before handling the message
        self.state
            .id_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(tagged_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        Ok(Message::from_lets_message(address, message))
    }
}

impl<T, F, A, AG> User<T, F, A, AG>
where
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Default,
    A::Base: Clone,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, usize)> + Default,
    F: PRP + Default + Clone,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
    T: for<'a> Transport<'a, Address = &'a A, Msg = TransportMessage>,
{
    /// Start a [`Messages`] stream to traverse the channel messages
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn messages(&mut self) -> Messages<T, F, A, AG> {
        IntoMessages::messages(self)
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
    pub async fn fetch_next_messages(&mut self) -> Result<Vec<Message<A>>> {
        self.messages().try_collect().await
    }
}

impl<T, F, A, AG> User<T, F, A, AG>
where
    F: PRP + Default,
    A: Link,
    A::Relative: Eq + Hash,
    for<'a> sizeof::Context: Mask<&'a A> + Mask<&'a A::Relative>,
    for<'a, 'b> wrap::Context<F, &'a mut [u8]>: Mask<&'b A> + Mask<&'b A::Relative>,
{
    pub async fn backup<P>(&mut self, pwd: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.state).await?;
        let buf_size = ctx.finalize();

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        let key: [u8; 32] = SpongosRng::<F>::new(pwd).gen();
        ctx.absorb(External::new(NBytes::new(&key)))?;
        ctx.wrap(&mut self.state).await?;
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );

        Ok(buf)
    }
}

impl<T, F, A, AG> User<T, F, A, AG>
where
    F: PRP + Default,
    A: Link + Default,
    A::Relative: Eq + Hash + Default,
    AG: Default,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Mask<&'b mut A> + Mask<&'b mut A::Relative>,
{
    pub async fn restore<B, P>(backup: B, pwd: P, transport: T) -> Result<Self>
    where
        P: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut ctx = unwrap::Context::<F, _>::new(backup.as_ref());
        let key: [u8; 32] = SpongosRng::<F>::new(pwd).gen();
        ctx.absorb(&External::new(NBytes::new(&key)))?;
        let mut state = State::default();
        ctx.unwrap(&mut state).await?;
        Ok(User {
            transport,
            address_generator: Default::default(),
            state,
        })
    }
}

#[async_trait(?Send)]
impl<F, A> ContentSizeof<State<F, A>> for sizeof::Context
where
    F: PRP,
    A: Link,
    A::Relative: Eq + Hash,
    for<'a> sizeof::Context: Mask<&'a A> + Mask<&'a A::Relative>,
{
    async fn sizeof(&mut self, user_state: &State<F, A>) -> Result<&mut Self> {
        self.mask(&user_state.user_id)?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let cursors = user_state.id_store.cursors();
        let amount_cursors = cursors.len();
        self.mask(Size::new(amount_cursors))?;
        for (subscriber, cursor) in cursors {
            self.mask(&subscriber)?.mask(Size::new(cursor))?;
        }

        let keys = user_state.id_store.keys();
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(&subscriber)?.mask(&ke_pk)?;
        }

        let psks = user_state.id_store.psks();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(&pskid)?.mask(&psk)?;
        }
        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, A> ContentWrap<State<F, A>> for wrap::Context<F, &'a mut [u8]>
where
    F: PRP,
    A: Link,
    A::Relative: Eq + Hash,
    for<'b> wrap::Context<F, &'a mut [u8]>: Mask<&'b A> + Mask<&'b A::Relative>,
{
    async fn wrap(&mut self, user_state: &mut State<F, A>) -> Result<&mut Self> {
        self.mask(&user_state.user_id)?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let cursors = user_state.id_store.cursors();
        let amount_cursors = cursors.len();
        self.mask(Size::new(amount_cursors))?;
        for (subscriber, cursor) in cursors {
            self.mask(&subscriber)?.mask(Size::new(cursor))?;
        }

        let keys = user_state.id_store.keys();
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(&subscriber)?.mask(&ke_pk)?;
        }

        let psks = user_state.id_store.psks();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(&pskid)?.mask(&psk)?;
        }
        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, A> ContentUnwrap<State<F, A>> for unwrap::Context<F, &'a [u8]>
where
    F: PRP + Default,
    A: Link + Default,
    A::Relative: Eq + Hash + Default,
    for<'b> unwrap::Context<F, &'a [u8]>: Mask<&'b mut A> + Mask<&'b mut A::Relative>,
{
    async fn unwrap(&mut self, user_state: &mut State<F, A>) -> Result<&mut Self> {
        self.mask(&mut user_state.user_id)?
            .mask(Maybe::new(&mut user_state.stream_address))?
            .mask(Maybe::new(&mut user_state.author_identifier))?;

        let mut amount_spongos = Size::default();
        self.mask(&mut amount_spongos)?;
        for _ in 0..amount_spongos.inner() {
            let mut address = A::Relative::default();
            let mut spongos = Spongos::default();
            self.mask(&mut address)?.mask(&mut spongos)?;
            user_state.spongos_store.insert(address, spongos);
        }

        let mut amount_cursors = Size::default();
        self.mask(&mut amount_cursors)?;
        for _ in 0..amount_cursors.inner() {
            let mut subscriber = Identifier::default();
            let mut cursor = Size::default();
            self.mask(&mut subscriber)?.mask(&mut cursor)?;
            user_state.id_store.insert_cursor(subscriber, cursor.inner());
        }

        let mut amount_keys = Size::default();
        self.mask(&mut amount_keys)?;
        for _ in 0..amount_keys.inner() {
            let mut subscriber = Identifier::default();
            let mut key = x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]);
            self.mask(&mut subscriber)?.mask(&mut key)?;
            user_state.id_store.insert_key(subscriber, key);
        }

        let mut amount_psks = Size::default();
        self.mask(&mut amount_psks)?;
        for _ in 0..amount_psks.inner() {
            let mut pskid = PskId::default();
            let mut psk = Psk::default();
            self.mask(&mut pskid)?.mask(&mut psk)?;
            user_state.id_store.insert_psk(pskid, psk);
        }

        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

impl<T, F, A, AG> IntoMessages<T, F, A, AG> for User<T, F, A, AG>
where
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Default,
    A::Base: Clone,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, usize)> + Default,
    F: PRP + Default + Clone,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
    T: for<'a> Transport<'a, Address = &'a A, Msg = TransportMessage>,
{
    fn messages(&mut self) -> Messages<'_, T, F, A, AG> {
        Messages::new(self)
    }
}

impl<T, F, A, AG> Debug for User<T, F, A, AG>
where
    A: Link,
    A::Relative: Display + Eq + Hash,
    F: PRP + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n* identifier: <{}>\n{:?}\n* messages:\n{}\n",
            self.identifier(),
            self.state.id_store,
            self.state
                .spongos_store
                .keys()
                .map(|key| format!("\t<{}>\n", key))
                .collect::<String>()
        )
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of this
/// fact is that two users with the same identity but different transport configurations are considered equal
impl<T, F, A, AG> PartialEq for User<T, F, A, AG>
where
    A: Link + PartialEq,
    A::Relative: Eq + Hash,
    F: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of this
/// fact is that two users with the same identity but different transport configurations are considered equal
impl<T, F, A, AG> Eq for User<T, F, A, AG>
where
    A: Link + PartialEq,
    A::Relative: Eq + Hash,
    F: PartialEq,
{
}
