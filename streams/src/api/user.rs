// Rust
use alloc::vec::Vec;
use core::{
    borrow::{
        Borrow,
        BorrowMut,
    },
    convert::TryFrom,
    fmt::Display,
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
    Spongos,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
    },
    link::{
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
    },
    message::{
        announce,
        keyload,
        message_types,
        signed_packet,
        subscribe,
        tagged_packet,
        unsubscribe,
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

struct User<T, TM, TSR, F, Address, LG>
where
    Address: Link,
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
    stream_address: Option<Address>,
    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    id_store: KeyStore,

    spongos_store: HashMap<Address::Relative, Spongos<F>>,
    // TODO: REMOVE
    // message_encoding: Vec<u8>, */
    //
    // TODO: REMOVE
    // uniform_payload_length: usize,
    transport: T,

    /// Address generator.
    link_generator: LG,

    phantom: PhantomData<(TM, TSR)>,
}

impl<T, TM, TSR, F, Address, LG> User<T, TM, TSR, F, Address, LG>
where
    // T: for<'a> Transport<&'a Address,
    // TransportMessage<Vec<u8>>,
    // TransportMessage<Vec<u8>>>,
    T: for<'a> Transport<&'a Address, TransportMessage<Vec<u8>>, TSR>,
    Address: Link + Display + Clone,
    Address::Relative: Clone + Eq + Hash + Default + Display,
    Address::Base: Clone,
    F: PRP + Default + Clone,
    for<'a, 'b> wrap::Context<F, &'a mut [u8]>: Absorb<&'b Address::Relative>,
    for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut Address::Relative>,
    // Hack necessary to workaround apparent infinite recursivity in Absorb<&mut Option<T>> for unwrap::Context.
    // Investigate!
    for<'a, 'b, 'c> &'a mut unwrap::Context<F, &'b [u8]>: Absorb<&'c mut Address::Relative>,
    for<'a> sizeof::Context: Absorb<&'a Address::Relative>,
    LG: for<'a> LinkGenerator<'a, Address::Relative, Data = (&'a Address::Base, Identifier, u64)>
        + LinkGenerator<'static, Address::Base, Data = (Identifier, u64)>
        + Default,
    // where
    //     F: PRP,
    //     L: Link,
    //     LG: LinkGenerator<L>,
    //     LS: LinkStore<F, L::Rel> + Default,
{
    /// Create a new User, storing [`UserIdentity`].
    fn new(user_id: Identity, transport: T) -> Self {
        // TODO: REMOVE
        // let message_encoding = ENCODING.as_bytes().to_vec();

        let mut key_store = KeyStore::default();
        // If User is using a Psk as their base Identifier, store the Psk
        if let Identity::Psk(psk) = user_id {
            key_store.insert_psk(psk.to_pskid::<F>(), psk);
        }

        Self {
            user_id,
            transport,
            id_store: key_store,
            // TODO: REMOVE
            // author_ke_pk: x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]),
            spongos_store: Default::default(),
            link_generator: Default::default(),
            stream_address: None,
            author_identifier: None,
            phantom: PhantomData, /* appaddr: None,
                                   * TODO: REMOVE
                                   * message_encoding,
                                   * uniform_payload_length: PAYLOAD_LENGTH, */
        }
    }

    /// Create a new stream (without announcing it). User now becomes Author.
    fn create_stream(&mut self, channel_idx: u64) -> Result<()> {
        if let Some(appaddr) = self.stream_address() {
            bail!(
                "Cannot create a channel, user is already registered to channel {}",
                appaddr
            );
        }
        let user_identifier = self.identifier();
        let stream_base_address = self.link_generator.gen((user_identifier, channel_idx));
        let stream_rel_address = self.link_generator.gen((&stream_base_address, user_identifier, 1));
        self.stream_address = Some(Address::from_parts(stream_base_address, stream_rel_address));
        self.author_identifier = Some(self.identifier());

        // to be removed once key-exchange is encapsulated within user-id
        let user_ke_pk = self
            .user_id
            ._ke_sk()
            .ok_or_else(|| anyhow!("this type of user cannot create channels"))?
            .public_key();
        match user_identifier {
            Identifier::PskId(_) => bail!("PSK users cannot create channels"),
            _ => {
                self.id_store.insert_key(self.identifier(), user_ke_pk);
            }
        }

        // self.author_id = Some(self.identifier());
        Ok(())
    }

    /// User's identifier
    fn identifier(&self) -> Identifier {
        self.user_id.to_identifier()
    }

    fn stream_address(&self) -> &Option<Address> {
        &self.stream_address
    }

    // /// Author's key exchange public key
    // fn author_key_exchange_public_key(&self) -> &x25519::PublicKey {
    //     &self.author_ke_pk
    // }

    // /// User's key exchange public key
    // fn key_exchange_public_key(&self) -> Result<x25519::PublicKey> {
    //     Ok(self.user_id.ke_kp()?.1)
    // }

    // /// Channel Author's signature public key
    // fn author_id(&self) -> Option<&Identifier> {
    //     self.author_id.as_ref()
    // }

    // TODO: REMOVE
    // /// Reset link store and key store to original state
    // fn reset_state(&mut self) -> Result<()> {
    //     match &self.appaddr {
    //         Some(appinst) => {
    //             self.key_store
    //                 .replace_cursors(Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM));

    //             let mut link_store = LS::default();
    //             let ann_state = self.link_store.lookup(appinst.rel())?;
    //             link_store.update(appinst.rel(), ann_state.0, ann_state.1)?;
    //             self.link_store = link_store;

    //             self.link_generator.reset(appinst.clone());
    //             Ok(())
    //         }
    //         None => err(UserNotRegistered),
    //     }
    // }

    // TODO: REMOVE
    // /// Save spongos and info associated to the message link
    // fn commit_wrapped(&mut self, wrapped: WrapState<F, L>, info: LS::Info) -> Result<L> {
    //     wrapped.commit(&mut self.link_store, info)
    // }

    async fn receive_message(&mut self, address: Address) -> Result<Message<Address>> {
        let msg = self.transport.recv_message(&address).await?;
        let preparsed = msg.parse_header::<F, Address::Relative>().await?;
        match preparsed.message_type() {
            message_types::ANNOUNCE => self.handle_announcement(address, preparsed).await,
            message_types::SUBSCRIPTION => self.handle_subscription(address, preparsed).await,
            unknown => Err(anyhow!("unexpected message type {}", unknown)),
        }
    }

    /// Prepare Announcement message.
    async fn announce(&mut self) -> Result<TSR> {
        // Check conditions
        let stream_address = self
            .stream_address
            .as_ref()
            .ok_or_else(|| anyhow!("before sending the announcement one must create the stream first"))?;

        // Update own's cursor
        // let user_cursor = Cursor::new(stream_address.relative().clone(), 1);
        let user_cursor = 1;

        // Prepare HDF and PCF
        let header = HDF::new(message_types::ANNOUNCE, user_cursor)?;
        let content = PCF::new_final_frame().with_content(announce::Wrap::new(&self.user_id));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        ensure!(
            self.transport.recv_message(stream_address).await.is_err(),
            anyhow!("stream with address '{}' already exists", stream_address)
        );
        let transported_msg = self.transport.send_message(stream_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.id_store.insert_cursor(self.identifier(), user_cursor);
        self.spongos_store.insert(stream_address.relative().clone(), spongos);
        Ok(transported_msg)
    }

    /// Bind Subscriber to the channel announced
    /// in the message.
    async fn handle_announcement<'a>(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage<'a, F, Address::Relative>,
    ) -> Result<Message<Address>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::ANNOUNCE,
            "message is not an announcement. Expected message-type {}, found {}",
            message_types::ANNOUNCE,
            preparsed.message_type()
        );
        if let Some(stream_address) = self.stream_address() {
            bail!("user is already connected to the stream {}", stream_address);
        }

        // Unwrap message
        let announcement = announce::Unwrap::default();
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
        // let cursor = Cursor::new(address.relative().clone(), message.header().sequence());
        let cursor = message.header().sequence();
        self.id_store.insert_cursor(author_id, cursor);

        Ok(Message::from_lets_message(address, message))
    }

    /// Prepare Subscribe message.
    async fn subscribe(&mut self, link_to: &Address::Relative) -> Result<TSR> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("before subscribing one must receive the announcement of a stream first"))?;

        // Update own's cursor
        let user_cursor = 1;
        let rel_address: Address::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), user_cursor));
        // let user_cursor = Cursor::new(rel_address.clone(), sequence);

        // Prepare HDF and PCF
        let header = HDF::new(message_types::SUBSCRIPTION, user_cursor)?.with_linked_msg_address(link_to.clone());
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
            .clone();
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .author_identifier
            .and_then(|author_id| self.id_store.get_x25519(&author_id))
            .expect("a user that already have an stream address must know the author identifier");
        let content = PCF::new_final_frame().with_content(subscribe::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            &self.user_id,
            author_ke_pk,
        ));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let transported_msg = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.id_store.insert_cursor(self.identifier(), user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(transported_msg)
    }

    async fn handle_subscription<'a>(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage<'a, F, Address::Relative>,
    ) -> Result<Message<Address>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::SUBSCRIPTION,
            "message is not a subscription. Expected message-type {}, found {}",
            message_types::SUBSCRIPTION,
            preparsed.message_type()
        );
        let stream_address = self
            .stream_address()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("before receiving subscriptions one must have created an stream first"))?;
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("subscription messages must contain the address of the message they are linked to in the header")
        })?;

        // Unwrap message
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(linked_msg_address)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", linked_msg_address))?
            .clone();
        let user_ke_sk = &self
            .user_id
            ._ke_sk()
            .expect("author of a stream must have an identity from which an x25519 secret-key can be derived");
        let subscription = subscribe::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, spongos) = preparsed.unwrap(subscription).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores

        // Update publisher's cursor
        let subscriber_identifier = message.payload().content().subscriber_id();
        self.id_store.insert_cursor(
            subscriber_identifier,
            message.header().sequence(), // Cursor::new(address.relative().clone(), message.header().sequence()),
        );

        Ok(Message::from_lets_message(address, message))
    }

    /// Prepare Subscribe message.
    async fn send_keyload<Subscribers>(&mut self, link_to: &Address::Relative, subscribers: Subscribers) -> Result<TSR>
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
        let rel_address: Address::Relative =
            self.link_generator
                .gen((stream_address.base(), self.identifier(), previous_user_cursor));
        let new_user_cursor = previous_user_cursor + 1;

        // Prepare HDF and PCF
        let header = HDF::new(message_types::SUBSCRIPTION, new_user_cursor)?.with_linked_msg_address(link_to.clone());
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(link_to)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?
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
            .collect::<Result<Vec<(Identifier, &[u8])>>>()?;
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut linked_msg_spongos,
            subscribers_with_keys,
            encryption_key,
            nonce,
            &self.user_id,
        ));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::from_parts(stream_address.into_base(), rel_address.clone());
        ensure!(
            self.transport.recv_message(&message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let transported_msg = self.transport.send_message(&message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.id_store.insert_cursor(self.identifier(), new_user_cursor);
        self.spongos_store.insert(rel_address, spongos);
        Ok(transported_msg)
    }

    async fn handle_keyload<'a>(
        &mut self,
        address: Address,
        preparsed: PreparsedMessage<'a, F, Address::Relative>,
    ) -> Result<Message<Address>> {
        // Check conditions
        ensure!(
            preparsed.message_type() == message_types::KEYLOAD,
            "message is not a keyload. Expected message-type {}, found {}",
            message_types::KEYLOAD,
            preparsed.message_type()
        );
        let stream_address = self.stream_address().as_ref().cloned().ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        let author_identifier = self.author_identifier.ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        let linked_msg_address = preparsed.linked_msg_address().as_ref().ok_or_else(|| {
            anyhow!("keyload messages must contain the address of the message they are linked to in the header")
        })?;

        // Unwrap message
        // Spongos must be cloned because wrapping mutates it
        let mut linked_msg_spongos = self
            .spongos_store
            .get(linked_msg_address)
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", linked_msg_address))?
            .clone();
        let user_ke_sk = &self
            .user_id
            ._ke_sk()
            .expect("author of a stream must have an identity from which an x25519 secret-key can be derived")
            .to_bytes();
        let keyload = keyload::Unwrap::new(
            &mut linked_msg_spongos,
            &self.user_id,
            user_ke_sk.as_slice(),
            author_identifier,
        );
        let (message, spongos) = preparsed.unwrap(keyload).await?;

        // Store spongos
        self.spongos_store.insert(address.relative().clone(), spongos);

        // Store message content into stores
        for subscriber in message.payload().content().subscribers() {
            self.id_store.insert_cursor_if_missing(*subscriber, 1)
        }

        // Update publisher's cursor
        self.id_store
            .insert_cursor(author_identifier, message.header().sequence());

        Ok(Message::from_lets_message(address, message))
    }
    // fn insert_subscriber(&mut self, id: Identifier, subscriber_xkey: x25519::PublicKey) -> Result<()> {
    //     match (!self.id_store.contains_subscriber(&id), &self.appaddr) {
    //         (_, None) => err!(UserNotRegistered),
    //         (true, Some(ref_link)) => {
    //             self.id_store
    //                 .insert_cursor(id, Cursor::new_at(ref_link.rel().clone(), 0, INIT_MESSAGE_NUM));
    //             self.id_store.insert_keys(id, subscriber_xkey)
    //         }
    //         (false, Some(ref_link)) => err!(UserAlreadyRegistered(id.to_string(), ref_link.base().to_string())),
    //     }
    // }

    // /// Prepare Subscribe message.
    // fn prepare_unsubscribe<'a>(
    //     &'a self,
    //     link_to: &'a L,
    // ) -> Result<PreparedMessage<F, L, unsubscribe::ContentWrap<'a, F, L>>> {
    //     match self.seq_no() {
    //         Some(seq_no) => {
    //             let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
    //             let header = HDF::new(msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(link_to.to_bytes()))
    //                 .with_content_type(UNSUBSCRIBE)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(msg_cursor.seq_no)
    //                 .with_identifier(self.id());
    //             let content = unsubscribe::ContentWrap {
    //                 link: link_to.rel(),
    //                 subscriber_id: &self.user_id,
    //                 _phantom: PhantomData,
    //             };
    //             Ok(PreparedMessage::new(header, content))
    //         }
    //         None => err!(SeqNumRetrievalFailure),
    //     }
    // }

    // /// Unsubscribe from the channel.
    // async fn unsubscribe(&self, link_to: &L) -> Result<WrappedMessage<F, L>> {
    //     self.prepare_unsubscribe(link_to)?.wrap(&self.spongos_store).await
    // }

    // async fn unwrap_unsubscribe<'a>(
    //     &self,
    //     preparsed: PreparsedMessage<'_, F, L>,
    // ) -> Result<UnwrappedMessage<F, L, unsubscribe::ContentUnwrap<F, L>>> {
    //     self.ensure_appinst(&preparsed)?;
    //     let content = unsubscribe::ContentUnwrap::default();
    //     preparsed.unwrap(&self.spongos_store, content).await
    // }

    // /// Confirm unsubscription request ownership and remove subscriber.
    // async fn handle_unsubscribe(&mut self, msg: BinaryMessage<L>, info: LS::Info) -> Result<()> {
    //     let preparsed = msg.parse_header().await?;
    //     let content = self
    //         .unwrap_unsubscribe(preparsed)
    //         .await?
    //         .commit(&mut self.spongos_store, info)?;
    //     self.remove_subscriber(content.subscriber_id.id)
    // }

    // fn remove_subscriber(&mut self, id: Identifier) -> Result<()> {
    //     match self.id_store.contains_subscriber(&id) {
    //         true => {
    //             self.id_store.remove(&id);
    //             Ok(())
    //         }
    //         false => err(UserNotRegistered),
    //     }
    // }

    // fn do_prepare_keyload<'a>(
    //     &'a self,
    //     header: HDF<L>,
    //     link_to: &'a L::Rel,
    //     keys: Vec<(Identifier, Vec<u8>)>,
    // ) -> Result<PreparedMessage<F, L, keyload::ContentWrap<'a, F, L>>> {
    //     let nonce = NBytes::from(prng::random_nonce());
    //     let key = NBytes::from(prng::random_key());
    //     let content = keyload::ContentWrap {
    //         link: link_to,
    //         nonce,
    //         key,
    //         keys,
    //         user_id: &self.user_id,
    //         _phantom: PhantomData,
    //     };
    //     Ok(PreparedMessage::new(header, content))
    // }

    // fn prepare_keyload<'a, 'b, I>(
    //     &'a self,
    //     link_to: &'a L,
    //     keys: I,
    // ) -> Result<PreparedMessage<F, L, keyload::ContentWrap<'a, F, L>>>
    // where
    //     I: IntoIterator<Item = &'b Identifier>,
    // {
    //     match self.seq_no() {
    //         Some(seq_no) => {
    //             let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
    //             let header = HDF::new(msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(link_to.to_bytes()))
    //                 .with_content_type(KEYLOAD)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(msg_cursor.seq_no)
    //                 .with_identifier(self.id());
    //             let filtered_keys = self.id_store.filter(keys);
    //             self.do_prepare_keyload(header, link_to.rel(), filtered_keys)
    //         }
    //         None => err!(SeqNumRetrievalFailure),
    //     }
    // }

    // fn prepare_keyload_for_everyone<'a>(
    //     &'a self,
    //     link_to: &'a L,
    // ) -> Result<PreparedMessage<F, L, keyload::ContentWrap<'a, F, L>>> {
    //     match self.seq_no() {
    //         Some(seq_no) => {
    //             let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
    //             let header = hdf::HDF::new(msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(link_to.to_bytes()))
    //                 .with_content_type(KEYLOAD)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(msg_cursor.seq_no)
    //                 .with_identifier(self.id());
    //             let keys = self.id_store.exchange_keys();
    //             self.do_prepare_keyload(header, link_to.rel(), keys)
    //         }
    //         None => err!(SeqNumRetrievalFailure),
    //     }
    // }

    // /// Create keyload message with a new session key shared with recipients
    // /// identified by pre-shared key IDs and by Ed25519 public keys.
    // async fn share_keyload<'a, I>(&mut self, link_to: &L, keys: I) -> Result<WrappedMessage<F, L>>
    // where
    //     I: IntoIterator<Item = &'a Identifier>,
    // {
    //     self.prepare_keyload(link_to, keys)?.wrap(&self.spongos_store).await
    // }

    // /// Create keyload message with a new session key shared with all Subscribers
    // /// known to Author.
    // async fn share_keyload_for_everyone(&mut self, link_to: &L) -> Result<WrappedMessage<F, L>> {
    //     self.prepare_keyload_for_everyone(link_to)?
    //         .wrap(&self.spongos_store)
    //         .await
    // }

    // async fn unwrap_keyload<'a>(
    //     &self,
    //     preparsed: PreparsedMessage<'_, F, L>,
    //     keys_lookup: KeysLookup<'a, F, L>,
    //     own_keys: OwnKeys<'a, F>,
    //     author_id: UserIdentity<F>,
    // ) -> Result<UnwrappedMessage<F, L, keyload::ContentUnwrap<F, L, KeysLookup<'a, F, L>, OwnKeys<'a, F>>>> {
    //     self.ensure_appinst(&preparsed)?;
    //     let content = keyload::ContentUnwrap::new(keys_lookup, own_keys, author_id);
    //     preparsed.unwrap(&self.spongos_store, content).await
    // }

    // /// Try unwrapping session key from keyload using Subscriber's pre-shared key or Ed25519 private key (if any).
    // async fn handle_keyload(&mut self, msg: &BinaryMessage<L>, info: LS::Info) -> Result<GenericMessage<L, bool>> {
    //     match &self.author_id {
    //         Some(author_id) => {
    //             let preparsed = msg.parse_header().await?;
    //             let prev_link = L::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
    //             // We need to borrow self.key_store, self.sig_kp and self.ke_kp at this scope
    //             // to leverage https://doc.rust-lang.org/nomicon/borrow-splitting.html
    //             let keys_lookup = KeysLookup::new(&self.id_store);
    //             let own_keys = OwnKeys(&self.user_id);

    //             let mut author_identity = UserIdentity::default();
    //             author_identity.id = *author_id;

    //             let unwrapped = self
    //                 .unwrap_keyload(preparsed, keys_lookup, own_keys, author_identity)
    //                 .await?;

    //             // Process a generic message containing the access right bool, also return the list of identifiers
    //             // to be stored.
    //             let (processed, keys) = if unwrapped.pcf.content.key.is_some() {
    //                 // Do not commit if key not found hence spongos state is invalid

    //                 // Presence of the key indicates the user is allowed
    //                 // Unwrapped nonce and key in content are not used explicitly.
    //                 // The resulting spongos state is joined into a protected message state.
    //                 let content = unwrapped.commit(&mut self.spongos_store, info)?;
    //                 (GenericMessage::new(msg.link.clone(), prev_link, true), content.key_ids)
    //             } else {
    //                 (
    //                     GenericMessage::new(msg.link.clone(), prev_link, false),
    //                     unwrapped.pcf.content.key_ids,
    //                 )
    //             };

    //             // Store any unknown publishers
    //             if let Some(appinst) = &self.appaddr {
    //                 for identifier in keys {
    //                     if !identifier.is_psk() && !self.id_store.contains_subscriber(&identifier) {
    //                         // Store at state 2 since 0 and 1 are reserved states
    //                         self.id_store
    //                             .insert_cursor(identifier, Cursor::new_at(appinst.rel().clone(), 0,
    // INIT_MESSAGE_NUM));                     }
    //                 }
    //             }

    //             Ok(processed)
    //         }
    //         None => err!(AuthorIdNotFound),
    //     }
    // }

    // /// Prepare SignedPacket message.
    // fn prepare_signed_packet<'a>(
    //     &'a self,
    //     link_to: &'a L,
    //     public_payload: &'a Bytes,
    //     masked_payload: &'a Bytes,
    // ) -> Result<PreparedMessage<F, L, signed_packet::ContentWrap<'a, F, L>>> {
    //     if self.id().is_psk() {
    //         return err(MessageBuildFailure);
    //     }
    //     match self.seq_no() {
    //         Some(seq_no) => {
    //             let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
    //             let header = HDF::new(msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(link_to.to_bytes()))
    //                 .with_content_type(SIGNED_PACKET)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(msg_cursor.seq_no)
    //                 .with_identifier(self.id());
    //             let content = signed_packet::ContentWrap {
    //                 link: link_to.rel(),
    //                 public_payload,
    //                 masked_payload,
    //                 user_id: &self.user_id,
    //                 _phantom: PhantomData,
    //             };
    //             Ok(PreparedMessage::new(header, content))
    //         }
    //         None => err!(SeqNumRetrievalFailure),
    //     }
    // }

    // /// Create a signed message with public and masked payload.
    // async fn sign_packet(
    //     &mut self,
    //     link_to: &L,
    //     public_payload: &Bytes,
    //     masked_payload: &Bytes,
    // ) -> Result<WrappedMessage<F, L>> {
    //     self.prepare_signed_packet(link_to, public_payload, masked_payload)?
    //         .wrap(&self.spongos_store)
    //         .await
    // }

    // async fn unwrap_signed_packet<'a>(
    //     &'a self,
    //     preparsed: PreparsedMessage<'a, F, L>,
    // ) -> Result<UnwrappedMessage<F, L, signed_packet::ContentUnwrap<F, L>>> {
    //     self.ensure_appinst(&preparsed)?;
    //     let content = signed_packet::ContentUnwrap::default();
    //     preparsed.unwrap(&self.spongos_store, content).await
    // }

    // /// Verify new Author's MSS public key and update Author's MSS public key.
    // async fn handle_signed_packet(
    //     &'_ mut self,
    //     msg: &BinaryMessage<L>,
    //     info: LS::Info,
    // ) -> Result<GenericMessage<L, (Identifier, Bytes, Bytes)>> {
    //     // TODO: pass author_pk to unwrap
    //     let preparsed = msg.parse_header().await?;
    //     let prev_link = L::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
    //     let content = self
    //         .unwrap_signed_packet(preparsed)
    //         .await?
    //         .commit(&mut self.spongos_store, info)?;

    //     let body = (content.user_id.id, content.public_payload, content.masked_payload);
    //     Ok(GenericMessage::new(msg.link.clone(), prev_link, body))
    // }

    // /// Prepare TaggedPacket message.
    // fn prepare_tagged_packet<'a>(
    //     &'a self,
    //     link_to: &'a L,
    //     public_payload: &'a Bytes,
    //     masked_payload: &'a Bytes,
    // ) -> Result<PreparedMessage<F, L, tagged_packet::ContentWrap<'a, F, L>>> {
    //     match self.seq_no() {
    //         Some(seq_no) => {
    //             let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
    //             let header = HDF::new(msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(link_to.to_bytes()))
    //                 .with_content_type(TAGGED_PACKET)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(msg_cursor.seq_no)
    //                 .with_identifier(self.id());
    //             let content = tagged_packet::ContentWrap {
    //                 link: link_to.rel(),
    //                 public_payload,
    //                 masked_payload,
    //                 _phantom: PhantomData,
    //             };
    //             Ok(PreparedMessage::new(header, content))
    //         }
    //         None => err!(SeqNumRetrievalFailure),
    //     }
    // }

    // /// Create a tagged (ie. MACed) message with public and masked payload.
    // /// Tagged messages must be linked to a secret spongos state, ie. keyload or a message linked to keyload.
    // async fn tag_packet(
    //     &self,
    //     link_to: &L,
    //     public_payload: &Bytes,
    //     masked_payload: &Bytes,
    // ) -> Result<WrappedMessage<F, L>> {
    //     self.prepare_tagged_packet(link_to, public_payload, masked_payload)?
    //         .wrap(&self.spongos_store)
    //         .await
    // }

    // async fn unwrap_tagged_packet(
    //     &self,
    //     preparsed: PreparsedMessage<'_, F, L>,
    // ) -> Result<UnwrappedMessage<F, L, tagged_packet::ContentUnwrap<F, L>>> {
    //     self.ensure_appinst(&preparsed)?;
    //     let content = tagged_packet::ContentUnwrap::default();
    //     preparsed.unwrap(&self.spongos_store, content).await
    // }

    // /// Get public payload, decrypt masked payload and verify MAC.
    // async fn handle_tagged_packet(
    //     &mut self,
    //     msg: &BinaryMessage<L>,
    //     info: LS::Info,
    // ) -> Result<GenericMessage<L, (Bytes, Bytes)>> {
    //     let preparsed = msg.parse_header().await?;
    //     let prev_link = L::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
    //     let content = self
    //         .unwrap_tagged_packet(preparsed)
    //         .await?
    //         .commit(&mut self.spongos_store, info)?;
    //     let body = (content.public_payload, content.masked_payload);
    //     Ok(GenericMessage::new(msg.link.clone(), prev_link, body))
    // }

    // async fn wrap_sequence(&mut self, ref_link: &L::Rel) -> Result<WrappedSequence<F, L>> {
    //     match self.id_store.get_cursor(self.id()) {
    //         Some(original_cursor) => {
    //             let previous_msg_link = L::from_base_rel(self.appaddr.as_ref().unwrap().base(),
    // &original_cursor.link);             let seq_msg_cursor = self.gen_seq_link(self.id(), &original_cursor.link);
    //             let header = HDF::new(seq_msg_cursor.link)
    //                 .with_previous_msg_link(Bytes(previous_msg_link.to_bytes()))
    //                 .with_content_type(SEQUENCE)?
    //                 .with_payload_length(1)?
    //                 .with_seq_num(seq_msg_cursor.seq_no)
    //                 .with_identifier(self.id());

    //             let content = sequence::ContentWrap::<L> {
    //                 link: &original_cursor.link,
    //                 id: *self.id(),
    //                 seq_num: original_cursor.seq_num(),
    //                 ref_link,
    //             };

    //             let wrapped = {
    //                 let prepared = PreparedMessage::new(header, content);
    //                 prepared.wrap(&self.spongos_store).await?
    //             };

    //             Ok(WrappedSequence {
    //                 cursor: original_cursor.clone(),
    //                 wrapped_message: wrapped,
    //             })
    //         }
    //         None => err(CursorNotFound),
    //     }
    // }

    // fn commit_sequence(
    //     &mut self,
    //     mut cursor: Cursor<L::Rel>,
    //     wrapped_state: WrapState<F, L>,
    //     info: LS::Info,
    // ) -> Result<Option<L>> {
    //     cursor.link = wrapped_state.link.rel().clone();
    //     cursor.next_seq();
    //     let id = *self.id();
    //     self.id_store.insert_cursor(id, cursor);
    //     let link = wrapped_state.link.clone();
    //     wrapped_state.commit(&mut self.spongos_store, info)?;
    //     Ok(Some(link))
    // }

    // async fn unwrap_sequence(
    //     &self,
    //     preparsed: PreparsedMessage<'_, F, L>,
    // ) -> Result<UnwrappedMessage<F, L, sequence::ContentUnwrap<L>>> {
    //     self.ensure_appinst(&preparsed)?;
    //     let content = sequence::ContentUnwrap::default();
    //     preparsed.unwrap(&self.spongos_store, content).await
    // }

    // // Fetch unwrapped sequence message to fetch referenced message
    // async fn handle_sequence(
    //     &mut self,
    //     msg: &BinaryMessage<L>,
    //     info: <LS as LinkStore<F, <L as HasLink>::Rel>>::Info,
    //     store: bool,
    // ) -> Result<GenericMessage<L, sequence::ContentUnwrap<L>>> {
    //     let preparsed = msg.parse_header().await?;
    //     let sender_id = preparsed.header.sender_id;
    //     let prev_link = L::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
    //     let content = self
    //         .unwrap_sequence(preparsed)
    //         .await?
    //         .commit(&mut self.spongos_store, info)?;
    //     if store {
    //         self.store_state(sender_id, msg.link.rel().clone())?;
    //     }
    //     Ok(GenericMessage::new(msg.link.clone(), prev_link, content))
    // }

    // // TODO: own seq_no should be stored outside of pk_store to avoid lookup and Option
    // fn seq_no(&self) -> Option<u32> {
    //     self.id_store.get_cursor(self.id()).map(|cursor| cursor.seq_no)
    // }

    // fn ensure_appinst<'a>(&self, preparsed: &PreparsedMessage<'a, F, L>) -> Result<()> {
    //     try_or!(self.appinst.is_some(), UserNotRegistered)?;
    //     try_or!(
    //         self.appinst.as_ref().unwrap().base() == preparsed.header.link.base(),
    //         MessageAppInstMismatch(
    //             self.appinst.as_ref().unwrap().base().to_string(),
    //             preparsed.header.link.base().to_string()
    //         )
    //     )?;
    //     Ok(())
    // }

    // fn store_psk(&mut self, pskid: PskId, psk: Psk) -> Result<()> {
    //     match &self.appaddr {
    //         Some(_) => {
    //             if self.id_store.contains_psk(&pskid) {
    //                 return err(PskAlreadyStored);
    //             }
    //             self.id_store.insert_psk(pskid.into(), psk)?;
    //             Ok(())
    //         }
    //         None => {
    //             if let Identifier::PskId(_) = self.id() {
    //                 self.id_store.insert_psk(pskid.into(), psk)
    //             } else {
    //                 err(UserNotRegistered)
    //             }
    //         }
    //     }
    // }

    // fn remove_psk(&mut self, pskid: PskId) -> Result<()> {
    //     match self.id_store.contains_psk(&pskid) {
    //         true => {
    //             self.id_store.remove(&pskid.into());
    //             Ok(())
    //         }
    //         false => err(UserNotRegistered),
    //     }
    // }

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
}

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
