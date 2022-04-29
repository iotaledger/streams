// Rust
use alloc::{
    format,
    string::String,
    vec::Vec,
};
use core::{
    borrow::{
        Borrow,
        BorrowMut,
    },
    convert::TryFrom,
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
    },
    hash::Hash,
    marker::PhantomData,
};

// 3rd-party
use anyhow::{
    anyhow,
    bail,
    ensure,
    Result,
};
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
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

// Streams
use spongos::{
    ddml::commands::{
        sizeof,
        unwrap,
        wrap,
        Absorb,
    },
    KeccakF1600,
    Spongos,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
        Psk,
        PskId,
    },
    link::{
        Address,
        AddressGenerator,
        AppAddr,
        Cursor,
        Link,
        LinkGenerator,
        MsgId,
    },
    message::{
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

const ENCODING: &str = "utf-8";
const PAYLOAD_LENGTH: usize = 32_000;

const ANN_MESSAGE_NUM: u64 = 0; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: u64 = 0; // Subscribe is always the first message of subscribers
const SEQ_MESSAGE_NUM: u64 = 1; // Reserved for sequence messages
const INIT_MESSAGE_NUM: u64 = 2; // First non-reserved message number

const UNKNOWN_APPADDR: &str = "unknown app address";

// TODO: REMOVE
// /// Sequence wrapping object
// ///
// /// This wrapping object contains the (wrapped) sequence message ([`WrappedMessage`]) to be
// /// sent and the [`Cursor`] of the user sending it.
// struct WrappedSequence<F, Link>
// where
//     Link: HasLink,
// {
//     cursor: Cursor<Link::Rel>,
//     wrapped_message: WrappedMessage<F, Link>,
// }

pub type User<T, TSR> = GenericUser<T, TSR, KeccakF1600, Address, AddressGenerator<KeccakF1600>>;

pub struct GenericUser<T, TSR, F, A, AG>
where
    A: Link,
{
    /// Users' Identity information, contains keys and logic for signing and verification
    user_id: Identity,

    // /// Author's public Id.
    // author_id: Option<Identifier>,

    // TODO: REMOVE
    // /// Author's Key Exchange Address
    //  author_ke_pk: x25519::PublicKey,
    /// Address of the stream announcement message
    ///
    /// None if channel is not created or user is not subscribed.
    stream_address: Option<A>,
    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    id_store: KeyStore,

    spongos_store: HashMap<A::Relative, Spongos<F>>,
    // TODO: REMOVE
    // message_encoding: Vec<u8>, */
    //
    // TODO: REMOVE
    // uniform_payload_length: usize,
    transport: T,

    /// Address generator.
    link_generator: AG,

    phantom: PhantomData<TSR>,
}

impl GenericUser<(), (), KeccakF1600, Address, AddressGenerator<KeccakF1600>> {
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T, TSR, F, A, AG> GenericUser<T, TSR, F, A, AG>
where
    A: Link,
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
            user_id,
            transport,
            id_store,
            spongos_store: Default::default(),
            link_generator: Default::default(),
            stream_address: None,
            author_identifier: None,
            phantom: PhantomData,
        }
    }

    /// User's identifier
    pub fn identifier(&self) -> Identifier {
        self.user_id.to_identifier()
    }

    pub(crate) fn stream_address(&self) -> &Option<A> {
        &self.stream_address
    }

    pub(crate) fn transport(&self) -> &T {
        &self.transport
    }
    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, u64)> + ExactSizeIterator + '_ {
        self.id_store.cursors()
    }

    pub(crate) fn subscribers(&self) -> impl Iterator<Item = Identifier> + '_ {
        self.id_store.subscribers()
    }

    fn insert_subscriber(&mut self, subscriber: Identifier) -> Result<bool> {
        let is_new = self.id_store.insert_cursor(subscriber, 1)
            && self.id_store.insert_key(
                subscriber,
                subscriber._ke_pk().ok_or_else(|| {
                    anyhow!("subscriber must have an identifier from which an x25519 public key can be derived")
                })?,
            );
        Ok(is_new)
    }

    pub fn remove_subscriber(&mut self, id: Identifier) -> bool {
        self.id_store.remove(&id)
    }

    pub fn store_psk(&mut self, psk: Psk) -> bool {
        self.id_store.insert_psk(psk.to_pskid::<F>(), psk)
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.id_store.remove_psk(pskid)
    }

    /// Create a new stream (without announcing it). User now becomes Author.
    pub fn create_stream(&mut self, channel_idx: u64) -> Result<()>
    where
        AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, u64)>
            + LinkGenerator<'static, A::Base, Data = (Identifier, u64)>,
        A: Display,
    {
        if let Some(appaddr) = self.stream_address() {
            bail!(
                "Cannot create a channel, user is already registered to channel {}",
                appaddr
            );
        }
        let user_identifier = self.identifier();
        let stream_base_address = self.link_generator.gen((user_identifier, channel_idx));
        let stream_rel_address = self.link_generator.gen((&stream_base_address, user_identifier, 1));
        self.stream_address = Some(A::from_parts(stream_base_address, stream_rel_address));
        self.author_identifier = Some(self.identifier());

        // to be removed once key-exchange is encapsulated within user-id
        let user_ke_pk = self
            .user_id
            ._ke_sk()
            .ok_or_else(|| anyhow!("this type of user cannot create channels"))?
            .public_key();
        self.id_store.insert_key(self.identifier(), user_ke_pk);

        Ok(())
    }
}

impl<T, TSR, F, A, AG> GenericUser<T, TSR, F, A, AG>
where
    T: for<'a> Transport<&'a A, TransportMessage<Vec<u8>>, TSR>,
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Display,
    F: PRP + Default + Clone,
    for<'a, 'b> wrap::Context<F, &'a mut [u8]>: Absorb<&'b A::Relative>,
    for<'a> sizeof::Context: Absorb<&'a A::Relative>,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, u64)>,
{
    /// Prepare Announcement message.
    pub async fn announce(&mut self) -> Result<SendResponse<A, TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address
            .as_ref()
            .ok_or_else(|| anyhow!("before sending the announcement one must create the stream first"))?;

        // Update own's cursor
        let user_cursor = 1;

        // Prepare HDF and PCF
        let header = HDF::new(message_types::ANNOUNCEMENT, user_cursor)?;
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(&self.user_id));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        ensure!(
            self.transport.recv_message(stream_address).await.is_err(),
            anyhow!("stream with address '{}' already exists", stream_address)
        );
        let send_response = self.transport.send_message(stream_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.id_store.insert_cursor(self.identifier(), user_cursor);
        self.spongos_store.insert(stream_address.relative().clone(), spongos);
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

        // Update own's cursor
        let user_cursor = 1;
        let rel_address: A::Relative = self
            .link_generator
            .gen((stream_address.base(), self.identifier(), user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .author_identifier
            .and_then(|author_id| self.id_store.get_x25519(&author_id))
            .expect("a user that already have an stream address must know the author identifier");
        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            &self.user_id,
            author_ke_pk,
        ));
        let header = HDF::new(message_types::SUBSCRIPTION, user_cursor)?.with_linked_msg_address(link_to);

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
        self.id_store.insert_cursor(self.identifier(), user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn unsubscribe(&mut self, link_to: A::Relative) -> Result<SendResponse<A, TSR>> {
        // Check conditions
        let stream_address = self.stream_address().as_ref().cloned().ok_or_else(|| {
            anyhow!("before sending a signed packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let previous_user_cursor = self.id_store.get_cursor(&self.identifier()).unwrap_or(1); // Account for subscribers added manually instead of sending a subscription message
        let new_user_cursor = previous_user_cursor + 1;
        let rel_address: A::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), new_user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content =
            PCF::new_final_frame().with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, &self.user_id));
        let header = HDF::new(message_types::UNSUBSCRIPTION, new_user_cursor)?.with_linked_msg_address(link_to);

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
        self.id_store.insert_cursor(self.identifier(), new_user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload<Subscribers>(
        &mut self,
        link_to: A::Relative,
        subscribers: Subscribers,
    ) -> Result<SendResponse<A, TSR>>
    where
        Subscribers: IntoIterator<Item = Identifier>,
        Subscribers::IntoIter: ExactSizeIterator,
    {
        // Check conditions
        let stream_address = self
            .stream_address()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("before sending a keyload one must create a stream first"))?;

        // Update own's cursor
        let previous_user_cursor = self
            .id_store
            .get_cursor(&self.identifier())
            .expect("author of a stream must have its cursor already stored");
        let new_user_cursor = previous_user_cursor + 1;
        let rel_address: A::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), new_user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        // let mut linked_msg_spongos = self
        //     .spongos_store
        //     .get(link_to)
        //     .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
        //     .clone();
        // TODO: EXPERIMENT: USE ANNOUNCEMENT SPONGOS FOR KEYLOADS, TO REMOVE SEQUENCE MESSAGES
        let mut announcement_spongos = self
            .spongos_store
            .get(stream_address.relative())
            .expect("a subscriber that has received an stream announcement must keep its spongos in store")
            // Spongos must be cloned because wrapping mutates it
            .clone();

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let subscribers_with_keys = subscribers
            .into_iter()
            .map(|subscriber| {
                Ok((
                    subscriber,
                    self.id_store
                        .get_exchange_key(&subscriber)
                        .ok_or_else(|| anyhow!("unknown subscriber '{}'", subscriber))?,
                ))
            })
            .collect::<Result<Vec<(Identifier, &[u8])>>>()?; // collect to handle possible error
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut announcement_spongos,
            subscribers_with_keys,
            encryption_key,
            nonce,
            &self.user_id,
        ));
        let header = HDF::new(message_types::KEYLOAD, new_user_cursor)?.with_linked_msg_address(link_to);

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
        self.id_store.insert_cursor(self.identifier(), new_user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload_for_all(&mut self, link_to: A::Relative) -> Result<SendResponse<A, TSR>> {
        self.send_keyload(
            link_to,
            // Alas, must collect to release the &self immutable borrow
            self.subscribers().collect::<Vec<Identifier>>(),
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
        let previous_user_cursor = self.id_store.get_cursor(&self.identifier()).unwrap_or(1); // Account for subscribers added manually instead of sending a subscription message
        let new_user_cursor = previous_user_cursor + 1;
        let rel_address: A::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), new_user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content = PCF::new_final_frame().with_content(signed_packet::Wrap::new(
            &mut linked_msg_spongos,
            &self.user_id,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(message_types::SIGNED_PACKET, new_user_cursor)?.with_linked_msg_address(link_to);

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
        self.id_store.insert_cursor(self.identifier(), new_user_cursor);
        self.spongos_store.insert(rel_address, spongos);
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
            anyhow!("before sending a signed packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let previous_user_cursor = self.id_store.get_cursor(&self.identifier()).unwrap_or(1); // Account for subscribers added manually instead of sending a subscription message
        let new_user_cursor = previous_user_cursor + 1;
        let rel_address: A::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), new_user_cursor));

        // Prepare HDF and PCF
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(&link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            self.identifier(),
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header = HDF::new(message_types::TAGGED_PACKET, new_user_cursor)?.with_linked_msg_address(link_to);

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
        self.id_store.insert_cursor(self.identifier(), new_user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }
}

impl<T, TSR, F, A, AG> GenericUser<T, TSR, F, A, AG>
where
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Default,
    F: PRP + Default + Clone,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
{
    pub async fn receive_message(&mut self, address: A) -> Result<Message<A>>
    where
        T: for<'a> Transport<&'a A, TransportMessage<Vec<u8>>, TSR>,
    {
        let msg = self.transport.recv_message(&address).await?;
        self.handle_message(address, msg).await
    }

    pub(crate) async fn handle_message(&mut self, address: A, msg: TransportMessage<Vec<u8>>) -> Result<Message<A>> {
        let preparsed = msg.parse_header::<F, A::Relative>().await?;
        match preparsed.message_type() {
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
        ensure!(
            preparsed.message_type() == message_types::ANNOUNCEMENT,
            "message is not an announcement. Expected message-type {}, found {}",
            message_types::ANNOUNCEMENT,
            preparsed.message_type()
        );
        if let Some(stream_address) = self.stream_address() {
            bail!("user is already connected to the stream {}", stream_address);
        }

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed.unwrap(announcement).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        let author_id = message.payload().content().author_id();
        let author_ke_pk = author_id
            ._ke_pk()
            .expect("Stream's author must have an identifier from which an x25519 public key can be derived");
        self.id_store.insert_key(author_id, author_ke_pk);
        self.stream_address = Some(address.clone());
        self.author_identifier = Some(author_id);

        // Update publisher's cursor
        let cursor = message.header().sequence();
        self.id_store.insert_cursor(author_id, cursor);

        Ok(Message::from_lets_message(address, message))
    }
    async fn handle_subscription<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::SUBSCRIPTION,
            "message is not a subscription. Expected message-type {}, found {}",
            message_types::SUBSCRIPTION,
            preparsed.message_type()
        );

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("subscription messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_ke_sk = &self
            .user_id
            ._ke_sk()
            .expect("author of a stream must have an identity from which an x25519 secret-key can be derived");
        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, spongos) = preparsed.unwrap(subscription).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        // Update publisher's cursor
        let subscriber_identifier = message.payload().content().subscriber_identifier();
        self.id_store.insert_cursor(
            subscriber_identifier,
            message.header().sequence(), // Cursor::new(address.relative().clone(), message.header().sequence()),
        );
        self.id_store.insert_key(
            subscriber_identifier,
            subscriber_identifier._ke_pk().ok_or_else(|| {
                anyhow!("subscriber must have an identifier from which an x25519 public key can be derived")
            })?,
        );

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_unsubscription<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::TAGGED_PACKET,
            "message is not a tagged packet. Expected message-type {}, found {}",
            message_types::TAGGED_PACKET,
            preparsed.message_type()
        );

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(unsubscription).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        // Update publisher's cursor
        self.id_store.insert_cursor(
            message.payload().content().subscriber_identifier(),
            message.header().sequence(),
        );

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_keyload<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        // TODO: CONSIDER REMOVE THE MESSAGE-TYPE CHECK, ISN'T IT REDUNDANT?
        ensure!(
            preparsed.message_type() == message_types::KEYLOAD,
            "message is not a keyload. Expected message-type {}, found {}",
            message_types::KEYLOAD,
            preparsed.message_type()
        );
        let stream_address = self
            .stream_address()
            .as_ref()
            .ok_or_else(|| anyhow!("before handling a keyload one must have received a stream announcement first"))?;

        // Unwrap message
        let author_identifier = self.author_identifier.ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        // let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
        //     anyhow!("keyload messages must contain the address of the message they are linked to in the header")
        // })?;
        // // Spongos must be cloned because wrapping mutates it
        // let mut linked_msg_spongos = self
        //     .spongos_store
        //     .get(linked_msg_address)
        //     .ok_or_else(|| anyhow!("message '{}' not found in spongos store", linked_msg_address))?
        //     .clone();
        // TODO: EXPERIMENT: USE ANNOUNCEMENT SPONGOS FOR KEYLOADS, TO REMOVE SEQUENCE MESSAGES
        let mut announcement_spongos = self
            .spongos_store
            .get(stream_address.relative())
            .expect("a subscriber that has received an stream announcement must keep its spongos in store")
            // Spongos must be cloned because wrapping mutates it
            .clone();

        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let user_ke_sk = self.user_id._ke();
        let keyload = keyload::Unwrap::new(&mut announcement_spongos, &self.user_id, &user_ke_sk, author_identifier);
        let (message, spongos) = preparsed.unwrap(keyload).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        for subscriber in message.payload().content().subscribers() {
            if !subscriber.is_psk() {
                self.id_store.insert_cursor_if_missing(*subscriber, 1)
            }
        }

        // Update publisher's cursor
        self.id_store
            .insert_cursor(author_identifier, message.header().sequence());

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_signed_packet<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::SIGNED_PACKET,
            "message is not a signed packet. Expected message-type {}, found {}",
            message_types::SIGNED_PACKET,
            preparsed.message_type()
        );

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let signed_packet = signed_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(signed_packet).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        // Update publisher's cursor
        self.id_store.insert_cursor(
            message.payload().content().publisher_identifier(),
            message.header().sequence(),
        );

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_tagged_packet<'a>(
        &mut self,
        address: A,
        preparsed: PreparsedMessage<Vec<u8>, F, A::Relative>,
    ) -> Result<Message<A>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::TAGGED_PACKET,
            "message is not a tagged packet. Expected message-type {}, found {}",
            message_types::TAGGED_PACKET,
            preparsed.message_type()
        );

        // Unwrap message
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.spongos_store.get(linked_msg_address) {
                // Spongos must be cloned because wrapping mutates it
                spongos.clone()
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(tagged_packet).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        // Update publisher's cursor
        self.id_store.insert_cursor(
            message.payload().content().publisher_identifier(),
            message.header().sequence(),
        );

        Ok(Message::from_lets_message(address, message))
    }
}

impl<T, TSR, F, A, AG> GenericUser<T, TSR, F, A, AG>
where
    A: Link + Display + Clone,
    A::Base: Clone,
    A::Relative: Clone + Eq + Hash + Default,
    F: PRP + Default + Clone,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
    T: for<'a> Transport<&'a A, TransportMessage<Vec<u8>>, TSR>,
    AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, u64)> + Default,
{
    /// Start a [`Messages`] stream to traverse the channel messages
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn messages(&mut self) -> Messages<T, TSR, F, A, AG> {
        IntoMessages::messages(self)
    }

    /// Iteratively fetches all the next messages until internal state has caught up
    ///
    /// If succeeded, returns the number of messages advanced.
    pub async fn sync_state(&mut self) -> Result<usize> {
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

// /// Generate the link of a message
// ///
// /// The link is generated from the link of the last message sent by the publishing user and its sequence number
// ///
// /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
// fn gen_link<I>(&self, id: I, last_link: &L::Rel, current_seq_no: u32) -> Cursor<L>
// where
//     I: AsRef<[u8]>,
// {
//     let new_link = self
//         .link_generator
//         .link_from(id, Cursor::new_at(last_link, 0, current_seq_no));
//     Cursor::new_at(new_link, 0, current_seq_no)
// }

// /// Generate the link of a sequence message of a user given the previous link of its referred message
// ///
// /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
// fn gen_seq_link<I>(&self, id: I, previous_link: &L::Rel) -> Cursor<L>
// where
//     I: AsRef<[u8]>,
// {
//     self.gen_link(id, previous_link, SEQ_MESSAGE_NUM)
// }

// /// Generate the next batch of message links to poll
// ///
// /// Given the set of users registered as participants of the channel and their current registered
// /// sequencing position, this method generates a set of new links to poll for new messages
// /// (one for each user, represented by its [`Identifier`]).
// ///
// /// Keep in mind that in multi-branch channels, the link returned corresponds to the next sequence message.
// ///
// /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
// fn gen_next_msg_links(&self) -> Vec<(Identifier, Cursor<L>)> {
//     // TODO: Turn it into iterator.
//     let mut ids = Vec::new();

//     // TODO: Do the same for self.user_id.id
//     for (id, cursor) in self.id_store.cursors() {
//         ids.push((*id, self.gen_seq_link(&id, &cursor.link)));
//     }
//     ids
// }

// fn store_state(&mut self, id: Identifier, link: L::Rel) -> Result<()> {
//     if let Some(cursor) = self.id_store.get_cursor_mut(&id) {
//         cursor.link = link;
//         cursor.next_seq();
//     }
//     Ok(())
// }

// fn fetch_state(&self) -> Result<Vec<(Identifier, Cursor<L>)>> {
//     let mut state = Vec::new();
//     try_or!(self.appinst.is_some(), UserNotRegistered)?;

//     for (
//         pk,
//         Cursor {
//             link,
//             branch_no,
//             seq_no,
//         },
//     ) in self.id_store.cursors()
//     {
//         let link = L::from_base_rel(self.appaddr.as_ref().unwrap().base(), link);
//         state.push((*pk, Cursor::new_at(link, *branch_no, *seq_no)))
//     }
//     Ok(state)
// }

// #[async_trait(?Send)]
// impl<F, Link, LG, LS> ContentSizeof<F> for User<F, Link, LG, LS>
// where
//     F: PRP,
//     Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
//     Link::Base: Eq + ToString,
//     Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
//     LG: LinkGenerator<Link>,
//     LS: LinkStore<F, Link::Rel> + Default,
//     LS::Info: AbsorbFallback<F>,
// {
//     async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
//         ctx.mask(<&NBytes<U32>>::from(&self.user_id.sig_sk()?.to_bytes()[..]))?
//             .absorb(<&Bytes>::from(&self.message_encoding))?
//             .absorb(Uint64(self.uniform_payload_length as u64))?;

//         let oneof_appinst = Uint8(if self.appaddr.is_some() { 1 } else { 0 });
//         ctx.absorb(oneof_appinst)?;
//         if let Some(ref appinst) = self.appaddr {
//             ctx.absorb(<&Fallback<Link>>::from(appinst))?;
//         }

//         let oneof_author_id = Uint8(if self.author_id.is_some() { 1 } else { 0 });
//         ctx.absorb(oneof_author_id)?;
//         if let Some(ref author_id) = self.author_id {
//             author_id.sizeof(ctx).await?;
//         }

//         let repeated_links = Size(self.spongos_store.len());
//         let keys = self.id_store.cursors();
//         let repeated_keys = Size(self.id_store.cursors_size());

//         ctx.absorb(repeated_links)?;
//         for (link, (s, info)) in self.spongos_store.iter() {
//             ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(link))?
//                 .mask(<&NBytes<F::CapacitySize>>::from(s.arr()))?
//                 .absorb(<&Fallback<<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info>>::from(
//                     info,
//                 ))?;
//         }

//         ctx.absorb(repeated_keys)?;
//         for (id, cursor) in keys {
//             let ctx = (*id).sizeof(ctx).await?;
//             ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(&cursor.link))?
//                 .absorb(Uint32(cursor.branch_no))?
//                 .absorb(Uint32(cursor.seq_no))?;
//         }
//         ctx.commit()?.squeeze(Mac(32))?;
//         Ok(ctx)
//     }
// }

// #[async_trait(?Send)]
// impl<F, Link, Store, LG, LS> ContentWrap<F, Store> for User<F, Link, LG, LS>
// where
//     F: PRP,
//     Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
//     Link::Base: Eq + ToString,
//     Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
//     Store: LinkStore<F, Link::Rel>,
//     LG: LinkGenerator<Link>,
//     LS: LinkStore<F, Link::Rel> + Default,
//     LS::Info: AbsorbFallback<F>,
// {
//     async fn wrap<'c, OS: io::OStream>(
//         &self,
//         store: &Store,
//         ctx: &'c mut wrap::Context<F, OS>,
//     ) -> Result<&'c mut wrap::Context<F, OS>> {
//         ctx.mask(<&NBytes<U32>>::from(&self.user_id.sig_sk()?.to_bytes()[..]))?
//             .absorb(<&Bytes>::from(&self.message_encoding))?
//             .absorb(Uint64(self.uniform_payload_length as u64))?;

//         let oneof_appinst = Uint8(if self.appaddr.is_some() { 1 } else { 0 });
//         ctx.absorb(oneof_appinst)?;
//         if let Some(ref appinst) = self.appaddr {
//             ctx.absorb(<&Fallback<Link>>::from(appinst))?;
//         }

//         let oneof_author_id = Uint8(if self.author_id.is_some() { 1 } else { 0 });
//         ctx.absorb(oneof_author_id)?;
//         if let Some(ref author_id) = self.author_id {
//             author_id.wrap(store, ctx).await?;
//         }

//         let repeated_links = Size(self.spongos_store.len());
//         let keys = self.id_store.cursors();
//         let repeated_keys = Size(self.id_store.cursors_size());

//         ctx.absorb(repeated_links)?;
//         for (link, (s, info)) in self.spongos_store.iter() {
//             ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(link))?
//                 .mask(<&NBytes<F::CapacitySize>>::from(s.arr()))?
//                 .absorb(<&Fallback<<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info>>::from(
//                     info,
//                 ))?;
//         }

//         ctx.absorb(repeated_keys)?;
//         for (id, cursor) in keys {
//             let ctx = id.clone().wrap(store.borrow(), ctx.borrow_mut()).await?;
//             ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(&cursor.borrow().link))?
//                 .absorb(Uint32(cursor.branch_no))?
//                 .absorb(Uint32(cursor.seq_no))?;
//         }
//         ctx.commit()?.squeeze(Mac(32))?;
//         Ok(ctx)
//     }
// }

// #[async_trait(?Send)]
// impl<F, Link, Store, LG, LS> ContentUnwrap<F, Store> for User<F, Link, LG, LS>
// where
//     F: PRP,
//     Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
//     Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
//     Store: LinkStore<F, Link::Rel>,
//     LG: LinkGenerator<Link>,
//     LS: LinkStore<F, Link::Rel> + Default,
//     LS::Info: Default + AbsorbFallback<F>,
// {
//     async fn unwrap<'c, IS: io::IStream>(
//         &mut self,
//         store: &Store,
//         ctx: &'c mut unwrap::Context<F, IS>,
//     ) -> Result<&'c mut unwrap::Context<F, IS>> {
//         let mut sig_sk_bytes = NBytes::<U32>::default();
//         let mut message_encoding = Bytes::new();
//         let mut uniform_payload_length = Uint64(0);
//         ctx.mask(&mut sig_sk_bytes)?
//             .absorb(&mut message_encoding)?
//             .absorb(&mut uniform_payload_length)?;

//         let mut oneof_appinst = Uint8(0);
//         ctx.absorb(&mut oneof_appinst)?
//             .guard(oneof_appinst.0 < 2, AppInstRecoveryFailure(oneof_appinst.0))?;

//         let appinst = if oneof_appinst.0 == 1 {
//             let mut appinst = Link::default();
//             ctx.absorb(<&mut Fallback<Link>>::from(&mut appinst))?;
//             Some(appinst)
//         } else {
//             None
//         };

//         let mut oneof_author_id = Uint8(0);
//         ctx.absorb(&mut oneof_author_id)?
//             .guard(oneof_author_id.0 < 2, AuthorSigPkRecoveryFailure(oneof_author_id.0))?;

//         let author_id = if oneof_author_id.0 == 1 {
//             let mut author_id = Identifier::default();
//             author_id.unwrap(store, ctx).await?;
//             Some(author_id)
//         } else {
//             None
//         };

//         let mut repeated_links = Size(0);
//         let mut link_store = LS::default();

//         ctx.absorb(&mut repeated_links)?;
//         for _ in 0..repeated_links.0 {
//             let mut link = Fallback(<Link as HasLink>::Rel::default());
//             let mut s = NBytes::<F::CapacitySize>::default();
//             let mut info = Fallback(<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info::default());
//             ctx.absorb(&mut link)?.mask(&mut s)?.absorb(&mut info)?;
//             let a: GenericArray<u8, F::CapacitySize> = s.into();
//             link_store.insert(&link.0, Inner::<F>::from(a), info.0)?;
//         }

//         let mut repeated_keys = Size(0);
//         let mut key_store = KeyStore::default();
//         ctx.absorb(&mut repeated_keys)?;
//         for _ in 0..repeated_keys.0 {
//             let mut link = Fallback(<Link as HasLink>::Rel::default());
//             let mut branch_no = Uint32(0);
//             let mut seq_no = Uint32(0);
//             let id = Identifier::default();
//             id.unwrap(ctx).await?;
//             ctx.absorb(&mut link)?.absorb(&mut branch_no)?.absorb(&mut seq_no)?;
//             key_store.insert_cursor(id, Cursor::new_at(link.0, branch_no.0, seq_no.0));
//         }

//         ctx.commit()?.squeeze(Mac(32))?;

//         let sig_sk = ed25519::SecretKey::from_bytes(<[u8; 32]>::try_from(sig_sk_bytes.as_ref())?);
//         let sig_pk = sig_sk.public_key();

//         self.user_id = UserIdentity::from((sig_sk, sig_pk));
//         self.spongos_store = link_store;
//         self.id_store = key_store;
//         self.author_id = author_id;
//         if let Some(ref seed) = appinst {
//             self.link_generator.reset(seed.clone());
//         }
//         self.appaddr = appinst;
//         self.message_encoding = message_encoding.0;
//         self.uniform_payload_length = uniform_payload_length.0 as usize;
//         Ok(ctx)
//     }
// }

// impl<F, Link, LG, LS> User<F, Link, LG, LS>
// where
//     F: PRP,
//     Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
//     Link::Base: Eq + ToString,
//     Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
//     LG: LinkGenerator<Link>,
//     LS: LinkStore<F, Link::Rel> + Default,
//     LS::Info: AbsorbFallback<F>,
// {
//     async fn export(&self, pwd: &str) -> Result<Vec<u8>> {
//         const VERSION: u8 = 0;
//         let buf_size = {
//             let mut ctx = sizeof::Context::<F>::new();
//             ctx.absorb(Uint8(VERSION))?;
//             self.sizeof(&mut ctx).await?;
//             ctx.size()
//         };

//         let mut buf = vec![0; buf_size];

//         {
//             let mut ctx = wrap::Context::new(&mut buf[..]);
//             let prng = prng::from_seed::<F>("IOTA Streams Channels app", pwd);
//             let key = NBytes::<U32>(prng.gen_arr("user export key"));
//             ctx.absorb(Uint8(VERSION))?.absorb(External(&key))?;
//             let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
//             self.wrap(&store, &mut ctx).await?;
//             try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
//         }

//         Ok(buf)
//     }
// }

// impl<F, Link, LG, LS> User<F, Link, LG, LS>
// where
//     F: PRP,
//     Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
//     Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
//     LG: LinkGenerator<Link>,
//     LS: LinkStore<F, Link::Rel> + Default,
//     LS::Info: Default + AbsorbFallback<F>,
// {
//     async fn import(bytes: &[u8], pwd: &str) -> Result<Self> {
//         const VERSION: u8 = 0;

//         let mut ctx = unwrap::Context::new(bytes);
//         let prng = prng::from_seed::<F>("IOTA Streams Channels app", pwd);
//         let key = NBytes::<U32>(prng.gen_arr("user export key"));
//         let mut version = Uint8(0);
//         ctx.absorb(&mut version)?
//             .guard(version.0 == VERSION, UserVersionRecoveryFailure(VERSION, version.0))?
//             .absorb(External(&key))?;

//         let mut user = User::default();
//         let store = EmptyLinkStore::<F, Link::Rel, ()>::default();
//         user.unwrap(&store, &mut ctx).await?;
//         try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
//         Ok(user)
//     }
// }

// // Newtype wrapper around KeyStore reference to be able to implement Lookup on it
// // Direct implementation is not possible due to KeyStore trait having type parameters itself
// struct KeysLookup<'a, F, Link>(&'a KeyStore<Link::Rel>, PhantomData<F>, PhantomData<Link>)
// where
//     F: PRP,
//     Link: HasLink;
// impl<'a, F, Link> KeysLookup<'a, F, Link>
// where
//     F: PRP,
//     Link: HasLink,
// {
//     fn new(key_store: &'a KeyStore<Link::Rel>) -> Self {
//         Self(key_store, PhantomData, PhantomData)
//     }
// }

// impl<F, Link> Lookup<&Identifier, psk::Psk> for KeysLookup<'_, F, Link>
// where
//     F: PRP,
//     Link: HasLink,
// {
//     fn lookup(&self, id: &Identifier) -> Option<psk::Psk> {
//         if let Identifier::PskId(pskid) = id {
//             self.0.get_psk(pskid).copied()
//         } else {
//             None
//         }
//     }
// }

// struct OwnKeys<'a, F>(&'a UserIdentity<F>);

// impl<'a, F: PRP> Lookup<&Identifier, x25519::SecretKey> for OwnKeys<'a, F> {
//     fn lookup(&self, id: &Identifier) -> Option<x25519::SecretKey> {
//         let Self(UserIdentity { id: self_id, .. }) = self;
//         if id == self_id {
//             self.0.ke_kp().map_or(None, |(secret, _public)| Some(secret))
//         } else {
//             None
//         }
//     }
// }

impl<T, TSR, F, A, AG> IntoMessages<T, TSR, F, A, AG> for GenericUser<T, TSR, F, A, AG>
where
    A: Link + Display + Clone,
    A::Relative: Clone + Eq + Hash + Default,
    A::Base: Clone,
    F: PRP + Default + Clone,
    AG: for<'b> LinkGenerator<'b, A::Relative, Data = (&'b A::Base, Identifier, u64)> + Default,
    for<'b, 'c> unwrap::Context<F, &'b [u8]>: Absorb<&'c mut A::Relative>,
    T: for<'b> Transport<&'b A, TransportMessage<Vec<u8>>, TSR>,
{
    fn messages(&mut self) -> Messages<'_, T, TSR, F, A, AG> {
        Messages::new(self)
    }
}

impl<T, TSR, F, A, AG> Debug for GenericUser<T, TSR, F, A, AG>
where
    A: Link,
    A::Relative: Display,
    F: PRP + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "* identifier: <{}>\n* {:?}\n* messages:\n{}",
            self.identifier(),
            self.id_store,
            self.spongos_store
                .keys()
                .map(|key| format!("\t<{}>\n", key))
                .collect::<String>()
        )
    }
}
