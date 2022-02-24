use core::{
    borrow::{
        Borrow,
        BorrowMut,
    },
    convert::TryFrom,
    marker::PhantomData,
};

use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use iota_streams_app::{
    id::{
        Identifier,
        UserIdentity,
    },
    message::{
        hdf::{
            FLAG_BRANCHING_MASK,
            HDF,
        },
        *,
    },
};
use iota_streams_core::{
    async_trait,
    err,
    prelude::{
        string::ToString,
        typenum::U32,
        Box,
        Vec,
    },
    prng,
    psk::{
        self,
        Psk,
        PskId,
    },
    sponge::prp::{
        Inner,
        PRP,
    },
    try_or,
    Errors::*,
    Result,
};
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{
        EmptyLinkStore,
        LinkStore,
    },
    types::*,
};

use crate::{
    api::{
        key_store::*,
        ChannelType,
    },
    message::*,
    Lookup,
};

const ANN_MESSAGE_NUM: u32 = 0; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: u32 = 0; // Subscribe is always the first message of subscribers
const SEQ_MESSAGE_NUM: u32 = 1; // Reserved for sequence messages
const INIT_MESSAGE_NUM: u32 = 2; // First non-reserved message number

/// Sequence wrapping object
///
/// When using multibranch mode, this wrapping object contains the (wrapped) sequence message ([`WrappedMessage`]) to be
/// sent and the [`Cursor`] of the user sending it.
///
/// When using single-branch mode, only the [`Cursor`] is needed, and no sequence message is sent.
pub enum WrappedSequence<F, Link>
where
    Link: HasLink,
{
    MultiBranch(Cursor<Link::Rel>, WrappedMessage<F, Link>),
    SingleBranch(Cursor<Link::Rel>),
    SingleDepth(Cursor<Link::Rel>),
    // Consider removing this option and returning Err instead
    None,
}

impl<F, Link> WrappedSequence<F, Link>
where
    Link: HasLink,
{
    pub fn single_branch(cursor: Cursor<Link::Rel>) -> Self {
        Self::SingleBranch(cursor)
    }

    pub fn multi_branch(cursor: Cursor<Link::Rel>, wrapped_message: WrappedMessage<F, Link>) -> Self {
        Self::MultiBranch(cursor, wrapped_message)
    }

    pub fn single_depth(cursor: Cursor<Link::Rel>) -> Self {
        Self::SingleDepth(cursor)
    }

    pub fn none() -> Self {
        Self::None
    }
}

pub struct User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink,
{
    // PRNG object used for Ed25519, X25519, Spongos key generation, etc.
    // pub(crate) prng: prng::Prng<F>,
    _phantom: PhantomData<F>,

    /// Users' Identity information, contains keys and logic for signing and verification
    pub(crate) user_id: UserIdentity<F>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    pub(crate) key_store: Keys,

    /// Author's public Id.
    pub(crate) author_id: Option<Identifier>,

    /// Author's Key Exchange Address
    pub(crate) author_ke_pk: x25519::PublicKey,

    /// Link generator.
    pub(crate) link_gen: LG,

    /// Link store.
    pub(crate) link_store: LS,

    /// Application instance - Link to the announce message.
    /// None if channel is not created or user is not subscribed.
    pub(crate) appinst: Option<Link>,

    /// Flags bit field
    pub flags: u8,

    pub use_psk: bool,

    pub message_encoding: Vec<u8>,

    pub uniform_payload_length: usize,

    /// Anchor message for the channel (can either be an announcement or keyload) - For single depth
    pub anchor: Option<Cursor<Link>>,
}

impl<F, Link, LG, LS, Keys> Default for User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F>,
{
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
            user_id: UserIdentity::default(),

            key_store: Keys::default(),
            author_id: None,
            author_ke_pk: x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]),
            link_gen: LG::default(),
            link_store: LS::default(),
            appinst: None,
            flags: 0,
            message_encoding: Vec::new(),
            uniform_payload_length: 0,
            use_psk: false,
            anchor: None,
        }
    }
}

impl<F, Link, LG, LS, Keys> User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + Default,
    Link::Base: Eq + ToString,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    Keys: KeyStore<Cursor<Link::Rel>, F>,
{
    /// Create a new User and generate Ed25519 key pair and corresponding X25519 key pair.
    pub fn gen(
        user_id: UserIdentity<F>,
        channel_type: ChannelType,
        message_encoding: Vec<u8>,
        uniform_payload_length: usize,
    ) -> Self {
        let flags: u8 = match channel_type {
            ChannelType::SingleBranch => 0,
            ChannelType::MultiBranch => 1,
            ChannelType::SingleDepth => 2,
        };

        Self {
            _phantom: PhantomData,
            user_id,

            key_store: Keys::default(),
            author_id: None,
            author_ke_pk: x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]),
            link_gen: LG::default(),
            link_store: LS::default(),
            appinst: None,
            flags,
            message_encoding,
            uniform_payload_length,
            use_psk: false,
            anchor: None,
        }
    }

    /// Create a new channel (without announcing it). User now becomes Author.
    pub fn create_channel(&mut self, channel_idx: u64) -> Result<()> {
        if self.appinst.is_some() {
            return err!(ChannelCreationFailure(
                self.appinst.as_ref().unwrap().base().to_string()
            ));
        }
        self.link_gen.gen(&self.user_id.id, channel_idx);
        let appinst = self.link_gen.get();

        match &self.user_id.id {
            Identifier::PskId(_pskid) => err(UnsupportedIdentifier)?,
            _ => {
                self.key_store
                    .cursors_mut()
                    .insert(self.user_id.id, Cursor::new_at(appinst.rel().clone(), 0, 2_u32));
                self.key_store.insert_keys(self.user_id.id, self.user_id.ke_kp()?.1)?;
            }
        }
        self.author_id = Some(self.user_id.id);
        self.anchor = Some(Cursor::new_at(appinst.clone(), 0, 2_u32));
        self.appinst = Some(appinst);
        Ok(())
    }

    /// User's identifier
    pub fn id(&self) -> &Identifier {
        &self.user_id.id
    }

    /// Author's key exchange public key
    fn author_key_exchange_public_key(&self) -> &x25519::PublicKey {
        &self.author_ke_pk
    }

    /// User's key exchange public key
    pub fn key_exchange_public_key(&self) -> Result<x25519::PublicKey> {
        Ok(self.user_id.ke_kp()?.1)
    }

    /// Channel Author's signature public key
    pub fn author_id(&self) -> Option<&Identifier> {
        self.author_id.as_ref()
    }

    /// Reset link store and key store to original state
    pub fn reset_state(&mut self) -> Result<()> {
        match &self.appinst {
            Some(appinst) => {
                self.key_store
                    .replace_cursors(Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM))?;

                let mut link_store = LS::default();
                let ann_state = self.link_store.lookup(appinst.rel())?;
                link_store.update(appinst.rel(), ann_state.0, ann_state.1)?;
                self.link_store = link_store;

                self.link_gen.reset(appinst.clone());
                Ok(())
            }
            None => err(UserNotRegistered),
        }
    }

    /// Save spongos and info associated to the message link
    pub fn commit_wrapped(&mut self, wrapped: WrapState<F, Link>, info: LS::Info) -> Result<Link> {
        wrapped.commit(&mut self.link_store, info)
    }

    /// Prepare Announcement message.
    pub fn prepare_announcement(&self) -> Result<PreparedMessage<F, Link, announce::ContentWrap<F>>> {
        // Create HDF for the first message in the channel.
        let msg_link = self.link_gen.get();
        let header = HDF::new(msg_link)
            .with_content_type(ANNOUNCE)?
            .with_payload_length(1)?
            .with_seq_num(ANN_MESSAGE_NUM)
            .with_identifier(&self.user_id.id);
        let content = announce::ContentWrap::new(&self.user_id, self.flags);
        Ok(PreparedMessage::new(header, content))
    }

    /// Create Announcement message.
    pub async fn announce(&self) -> Result<WrappedMessage<F, Link>> {
        self.prepare_announcement()?.wrap(&self.link_store).await
    }

    pub async fn unwrap_announcement(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, announce::ContentUnwrap<F>>> {
        if let Some(appinst) = &self.appinst {
            try_or!(
                appinst == &preparsed.header.link,
                UserAlreadyRegistered(self.user_id.id.to_string(), appinst.base().to_string())
            )?;
        }

        let content = announce::ContentUnwrap::<F>::default();
        let r = preparsed.unwrap(&self.link_store, content).await;
        r
    }

    /// Bind Subscriber (or anonymously subscribe) to the channel announced
    /// in the message.
    pub async fn handle_announcement(&mut self, msg: &BinaryMessage<Link>, info: LS::Info) -> Result<()> {
        let preparsed = msg.parse_header().await?;
        try_or!(
            preparsed.content_type() == ANNOUNCE,
            NotAnnouncement(preparsed.content_type())
        )?;

        let unwrapped = self.unwrap_announcement(preparsed).await?;
        let link = unwrapped.link.clone();
        let content = unwrapped.commit(&mut self.link_store, info)?;
        let author_id = content.author_id;
        let author_ke_pk = content.ke_pk;
        // TODO: check commit after message is done / before joined

        // TODO: Verify trust to Author's public key?
        // At the moment the Author is trusted unconditionally.

        // TODO: Verify appinst (address) == public key.
        // At the moment the Author is free to choose any address, not tied to PK.

        let cursor = Cursor::new_at(link.rel().clone(), 0, INIT_MESSAGE_NUM);
        match &author_id.id {
            Identifier::PskId(_pskid) => err(UnsupportedIdentifier)?,
            _ => self.key_store.cursors_mut().insert(author_id.id, cursor.clone()),
        };
        match &self.user_id.id {
            Identifier::PskId(_pskid) => err(UnsupportedIdentifier)?,
            _ => self.key_store.cursors_mut().insert(self.user_id.id, cursor),
        };

        self.key_store.insert_keys(author_id.id, author_ke_pk.clone())?;
        self.key_store.insert_keys(self.user_id.id, self.user_id.ke_kp()?.1)?;

        // Reset link_gen
        self.link_gen.reset(link.clone());
        self.anchor = Some(Cursor::new_at(link.clone(), 0, INIT_MESSAGE_NUM));
        self.appinst = Some(link);
        self.author_id = Some(author_id.id);
        self.author_ke_pk = author_ke_pk;
        self.flags = content.flags.0;
        Ok(())
    }

    /// Prepare Subscribe message.
    pub fn prepare_subscribe<'a>(
        &'a self,
        link_to: &'a Link,
    ) -> Result<PreparedMessage<F, Link, subscribe::ContentWrap<'a, F, Link>>> {
        // TODO: Remove need for get_ke_pk, store author ke pk as part of user
        if let Some(_) = &self.author_id {
            let msg_cursor = self.gen_link(self.user_id.id, link_to.rel(), SUB_MESSAGE_NUM);
            let header = HDF::new(msg_cursor.link)
                .with_previous_msg_link(Bytes(link_to.to_bytes()))
                .with_content_type(SUBSCRIBE)?
                .with_payload_length(1)?
                .with_seq_num(msg_cursor.seq_no)
                .with_identifier(&self.user_id.id);
            let unsubscribe_key = NBytes::from(prng::random_key());
            let content = subscribe::ContentWrap {
                link: link_to.rel(),
                unsubscribe_key,
                subscriber_id: &self.user_id,
                author_ke_pk: self.author_key_exchange_public_key(),
                _phantom: PhantomData,
            };
            Ok(PreparedMessage::new(header, content))
        } else {
            err!(AuthorIdNotFound)
        }
    }

    /// Subscribe to the channel.
    pub async fn subscribe(&self, link_to: &Link) -> Result<WrappedMessage<F, Link>> {
        self.prepare_subscribe(link_to)?.wrap(&self.link_store).await
    }

    #[allow(clippy::needless_lifetimes)] // See https://github.com/rust-lang/rust-clippy/issues/7271
    pub async fn unwrap_subscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
        author_ke_sk: &'a x25519::SecretKey,
    ) -> Result<UnwrappedMessage<F, Link, subscribe::ContentUnwrap<'a, F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = subscribe::ContentUnwrap::new(author_ke_sk)?;
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub async fn handle_subscribe(&mut self, msg: &BinaryMessage<Link>, info: LS::Info) -> Result<()> {
        let preparsed = msg.parse_header().await?;
        // TODO: check content type
        let self_ke_kp = self.user_id.ke_kp()?;

        let content = self
            .unwrap_subscribe(preparsed, &self_ke_kp.0)
            .await?
            .commit(&mut self.link_store, info)?;
        // TODO: trust content.subscriber_sig_pk
        // TODO: remove unused unsubscribe_key because it is unnecessary for verification anymore
        let subscriber_id = content.subscriber_id;
        self.insert_subscriber(subscriber_id.id, content.subscriber_xkey)
    }

    pub fn insert_subscriber(&mut self, id: Identifier, subscriber_xkey: x25519::PublicKey) -> Result<()> {
        match (!self.key_store.cursors().contains_key(&id), &self.appinst) {
            (_, None) => err!(UserNotRegistered),
            (true, Some(ref_link)) => {
                self.key_store
                    .cursors_mut()
                    .insert(id, Cursor::new_at(ref_link.rel().clone(), 0, INIT_MESSAGE_NUM));
                self.key_store.insert_keys(id, subscriber_xkey)
            }
            (false, Some(ref_link)) => err!(UserAlreadyRegistered(id.to_string(), ref_link.base().to_string())),
        }
    }

    /// Prepare Subscribe message.
    pub fn prepare_unsubscribe<'a>(
        &'a self,
        link_to: &'a Link,
    ) -> Result<PreparedMessage<F, Link, unsubscribe::ContentWrap<'a, F, Link>>> {
        match self.seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.user_id.id, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(UNSUBSCRIBE)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.user_id.id);
                let content = unsubscribe::ContentWrap {
                    link: link_to.rel(),
                    subscriber_id: &self.user_id,
                    _phantom: PhantomData,
                };
                Ok(PreparedMessage::new(header, content))
            }
            None => err!(SeqNumRetrievalFailure),
        }
    }

    /// Unsubscribe from the channel.
    pub async fn unsubscribe(&self, link_to: &Link) -> Result<WrappedMessage<F, Link>> {
        self.prepare_unsubscribe(link_to)?.wrap(&self.link_store).await
    }

    pub async fn unwrap_unsubscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, unsubscribe::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = unsubscribe::ContentUnwrap::default();
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Confirm unsubscription request ownership and remove subscriber.
    pub async fn handle_unsubscribe(&mut self, msg: BinaryMessage<Link>, info: LS::Info) -> Result<()> {
        let preparsed = msg.parse_header().await?;
        let content = self
            .unwrap_unsubscribe(preparsed)
            .await?
            .commit(&mut self.link_store, info)?;
        self.remove_subscriber(content.subscriber_id.id)
    }

    pub fn remove_subscriber(&mut self, id: Identifier) -> Result<()> {
        match self.key_store.cursors().contains_key(&id) {
            true => {
                self.key_store.remove(&id);
                Ok(())
            }
            false => err(UserNotRegistered),
        }
    }

    fn do_prepare_keyload<'a>(
        &'a self,
        header: HDF<Link>,
        link_to: &'a Link::Rel,
        keys: Vec<(Identifier, Vec<u8>)>,
    ) -> Result<PreparedMessage<F, Link, keyload::ContentWrap<'a, F, Link>>> {
        let nonce = NBytes::from(prng::random_nonce());
        let key = NBytes::from(prng::random_key());
        let content = keyload::ContentWrap {
            link: link_to,
            nonce,
            key,
            keys,
            user_id: &self.user_id,
            _phantom: PhantomData,
        };
        Ok(PreparedMessage::new(header, content))
    }

    pub fn prepare_keyload<'a, 'b, I>(
        &'a self,
        link_to: &'a Link,
        keys: I,
    ) -> Result<PreparedMessage<F, Link, keyload::ContentWrap<'a, F, Link>>>
    where
        I: IntoIterator<Item = &'b Identifier>,
    {
        match self.seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.user_id.id, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(KEYLOAD)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.user_id.id);
                let filtered_keys = self.key_store.filter(keys);
                self.do_prepare_keyload(header, link_to.rel(), filtered_keys)
            }
            None => err!(SeqNumRetrievalFailure),
        }
    }

    pub fn prepare_keyload_for_everyone<'a>(
        &'a self,
        link_to: &'a Link,
    ) -> Result<PreparedMessage<F, Link, keyload::ContentWrap<'a, F, Link>>> {
        match self.seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.user_id.id, link_to.rel(), seq_no);
                let header = hdf::HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(KEYLOAD)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.user_id.id);
                let keys = self.key_store.keys();
                self.do_prepare_keyload(header, link_to.rel(), keys)
            }
            None => err!(SeqNumRetrievalFailure),
        }
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by Ed25519 public keys.
    pub async fn share_keyload<'a, I>(&mut self, link_to: &Link, keys: I) -> Result<WrappedMessage<F, Link>>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        self.prepare_keyload(link_to, keys)?.wrap(&self.link_store).await
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub async fn share_keyload_for_everyone(&mut self, link_to: &Link) -> Result<WrappedMessage<F, Link>> {
        self.prepare_keyload_for_everyone(link_to)?.wrap(&self.link_store).await
    }

    pub async fn unwrap_keyload<'a>(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
        keys_lookup: KeysLookup<'a, F, Link, Keys>,
        own_keys: OwnKeys<'a, F>,
        author_id: UserIdentity<F>,
    ) -> Result<UnwrappedMessage<F, Link, keyload::ContentUnwrap<F, Link, KeysLookup<'a, F, Link, Keys>, OwnKeys<'a, F>>>>
    {
        self.ensure_appinst(&preparsed)?;
        let content = keyload::ContentUnwrap::new(keys_lookup, own_keys, author_id);
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or Ed25519 private key (if any).
    pub async fn handle_keyload(
        &mut self,
        msg: &BinaryMessage<Link>,
        info: LS::Info,
    ) -> Result<GenericMessage<Link, bool>> {
        match &self.author_id {
            Some(author_id) => {
                let preparsed = msg.parse_header().await?;
                let prev_link = Link::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
                let seq_no = preparsed.header.seq_num;
                // We need to borrow self.key_store, self.sig_kp and self.ke_kp at this scope
                // to leverage https://doc.rust-lang.org/nomicon/borrow-splitting.html
                let keys_lookup = KeysLookup::new(&self.key_store);
                let own_keys = OwnKeys(&self.user_id);

                let mut author_identity = UserIdentity::default();
                author_identity.id = *author_id;

                let unwrapped = self
                    .unwrap_keyload(preparsed, keys_lookup, own_keys, author_identity)
                    .await?;

                // Process a generic message containing the access right bool, also return the list of identifiers
                // to be stored.
                let (processed, keys) = if unwrapped.pcf.content.key.is_some() {
                    // Do not commit if key not found hence spongos state is invalid

                    // Presence of the key indicates the user is allowed
                    // Unwrapped nonce and key in content are not used explicitly.
                    // The resulting spongos state is joined into a protected message state.
                    let content = unwrapped.commit(&mut self.link_store, info)?;
                    (GenericMessage::new(msg.link.clone(), prev_link, true), content.key_ids)
                } else {
                    (
                        GenericMessage::new(msg.link.clone(), prev_link, false),
                        unwrapped.pcf.content.key_ids,
                    )
                };

                // Store any unknown publishers
                if let Some(appinst) = &self.appinst {
                    for identifier in keys {
                        if !self.key_store.cursors().contains_key(&identifier) {
                            // Store at state 2 since 0 and 1 are reserved states
                            self.key_store
                                .cursors_mut()
                                .insert(identifier, Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM));
                        }
                    }
                }

                if !self.is_multi_branching() {
                    self.store_state_for_all(msg.link.rel().clone(), seq_no.0 as u32 + 1)?;
                    if self.is_single_depth() {
                        self.anchor = Some(Cursor::new_at(msg.link.clone(), 0, seq_no.0 as u32 + 1));
                    }
                }
                Ok(processed)
            }
            None => err!(AuthorIdNotFound),
        }
    }

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(
        &'a self,
        link_to: &'a Link,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<F, Link, signed_packet::ContentWrap<'a, F, Link>>> {
        if self.id().is_psk() {
            return err(MessageBuildFailure);
        }
        match self.seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.user_id.id, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(SIGNED_PACKET)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.user_id.id);
                let content = signed_packet::ContentWrap {
                    link: link_to.rel(),
                    public_payload,
                    masked_payload,
                    user_id: &self.user_id,
                    _phantom: PhantomData,
                };
                Ok(PreparedMessage::new(header, content))
            }
            None => err!(SeqNumRetrievalFailure),
        }
    }

    /// Create a signed message with public and masked payload.
    pub async fn sign_packet(
        &mut self,
        link_to: &Link,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_signed_packet(link_to, public_payload, masked_payload)?
            .wrap(&self.link_store)
            .await
    }

    pub async fn unwrap_signed_packet<'a>(
        &'a self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, signed_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = signed_packet::ContentUnwrap::default();
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Verify new Author's MSS public key and update Author's MSS public key.
    pub async fn handle_signed_packet(
        &'_ mut self,
        msg: &BinaryMessage<Link>,
        info: LS::Info,
    ) -> Result<GenericMessage<Link, (Identifier, Bytes, Bytes)>> {
        // TODO: pass author_pk to unwrap
        let preparsed = msg.parse_header().await?;
        let prev_link = Link::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
        let seq_no = preparsed.header.seq_num;
        let content = self
            .unwrap_signed_packet(preparsed)
            .await?
            .commit(&mut self.link_store, info)?;
        if !self.is_multi_branching() {
            let link = if self.is_single_depth() {
                self.fetch_anchor()?.link.rel().clone()
            } else {
                msg.link.rel().clone()
            };
            self.store_state_for_all(link, seq_no.0 as u32 + 1)?;
        }

        let body = (content.user_id.id, content.public_payload, content.masked_payload);
        Ok(GenericMessage::new(msg.link.clone(), prev_link, body))
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a self,
        link_to: &'a Link,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<F, Link, tagged_packet::ContentWrap<'a, F, Link>>> {
        match self.seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.id(), link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(TAGGED_PACKET)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(self.id());
                let content = tagged_packet::ContentWrap {
                    link: link_to.rel(),
                    public_payload,
                    masked_payload,
                    _phantom: PhantomData,
                };
                Ok(PreparedMessage::new(header, content))
            }
            None => err!(SeqNumRetrievalFailure),
        }
    }

    /// Create a tagged (ie. MACed) message with public and masked payload.
    /// Tagged messages must be linked to a secret spongos state, ie. keyload or a message linked to keyload.
    pub async fn tag_packet(
        &self,
        link_to: &Link,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_tagged_packet(link_to, public_payload, masked_payload)?
            .wrap(&self.link_store)
            .await
    }

    pub async fn unwrap_tagged_packet(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, tagged_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = tagged_packet::ContentUnwrap::default();
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub async fn handle_tagged_packet(
        &mut self,
        msg: &BinaryMessage<Link>,
        info: LS::Info,
    ) -> Result<GenericMessage<Link, (Bytes, Bytes)>> {
        let preparsed = msg.parse_header().await?;
        let prev_link = Link::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
        let seq_no = preparsed.header.seq_num;
        let content = self
            .unwrap_tagged_packet(preparsed)
            .await?
            .commit(&mut self.link_store, info)?;
        if !self.is_multi_branching() {
            let link = if self.is_single_depth() {
                self.fetch_anchor()?.link.rel().clone()
            } else {
                msg.link.rel().clone()
            };
            self.store_state_for_all(link, seq_no.0 as u32 + 1)?;
        }

        let body = (content.public_payload, content.masked_payload);
        Ok(GenericMessage::new(msg.link.clone(), prev_link, body))
    }

    pub async fn wrap_sequence(&mut self, ref_link: &Link::Rel) -> Result<WrappedSequence<F, Link>> {
        match self.key_store.cursors().get(self.id()) {
            Some(original_cursor) => {
                if (self.flags & FLAG_BRANCHING_MASK) != 0 {
                    let previous_msg_link =
                        Link::from_base_rel(self.appinst.as_ref().unwrap().base(), &original_cursor.link);
                    let seq_msg_cursor = self.gen_seq_link(self.id(), &original_cursor.link);
                    let header = HDF::new(seq_msg_cursor.link)
                        .with_previous_msg_link(Bytes(previous_msg_link.to_bytes()))
                        .with_content_type(SEQUENCE)?
                        .with_payload_length(1)?
                        .with_seq_num(seq_msg_cursor.seq_no)
                        .with_identifier(self.id());

                    let content = sequence::ContentWrap::<Link> {
                        link: &original_cursor.link,
                        id: *self.id(),
                        seq_num: original_cursor.seq_num(),
                        ref_link,
                    };

                    let wrapped = {
                        let prepared = PreparedMessage::new(header, content);
                        prepared.wrap(&self.link_store).await?
                    };

                    Ok(WrappedSequence::multi_branch(original_cursor.clone(), wrapped))
                } else if self.is_single_depth() {
                    Ok(WrappedSequence::SingleDepth(original_cursor.clone()))
                } else {
                    let full_cursor = self.gen_link(self.user_id.id, ref_link, original_cursor.seq_no);
                    let rel_cursor = Cursor::new_at(full_cursor.link.rel().clone(), 0, full_cursor.seq_no);
                    Ok(WrappedSequence::single_branch(rel_cursor))
                }
            }
            None => Ok(WrappedSequence::none()),
        }
    }

    pub fn commit_sequence(
        &mut self,
        mut cursor: Cursor<Link::Rel>,
        wrapped_state: WrapState<F, Link>,
        info: LS::Info,
    ) -> Result<Option<Link>> {
        cursor.link = wrapped_state.link.rel().clone();
        cursor.next_seq();
        let id = *self.id();
        self.key_store.cursors_mut().insert(id, cursor);
        let link = wrapped_state.link.clone();
        wrapped_state.commit(&mut self.link_store, info)?;
        Ok(Some(link))
    }

    pub fn commit_sequence_to_all(&mut self, cursor: Cursor<Link::Rel>) -> Result<()> {
        self.store_state_for_all(cursor.link, cursor.seq_no + 1)?;
        Ok(())
    }

    pub async fn unwrap_sequence(
        &self,
        preparsed: PreparsedMessage<'_, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, sequence::ContentUnwrap<Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = sequence::ContentUnwrap::default();
        preparsed.unwrap(&self.link_store, content).await
    }

    // Fetch unwrapped sequence message to fetch referenced message
    pub async fn handle_sequence(
        &mut self,
        msg: &BinaryMessage<Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
        store: bool,
    ) -> Result<GenericMessage<Link, sequence::ContentUnwrap<Link>>> {
        let preparsed = msg.parse_header().await?;
        let sender_id = preparsed.header.sender_id;
        let prev_link = Link::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
        let content = self
            .unwrap_sequence(preparsed)
            .await?
            .commit(&mut self.link_store, info)?;
        if store {
            self.store_state(sender_id, msg.link.rel().clone())?;
        }
        Ok(GenericMessage::new(msg.link.clone(), prev_link, content))
    }

    pub fn is_multi_branching(&self) -> bool {
        (self.flags & FLAG_BRANCHING_MASK) != 0
    }

    pub fn is_single_depth(&self) -> bool {
        self.flags == 2
    }

    // TODO: own seq_no should be stored outside of pk_store to avoid lookup and Option
    pub fn seq_no(&self) -> Option<u32> {
        self.key_store
            .cursors()
            .get(&self.user_id.id)
            .map(|cursor| cursor.seq_no)
    }

    pub fn ensure_appinst<'a>(&self, preparsed: &PreparsedMessage<'a, F, Link>) -> Result<()> {
        try_or!(self.appinst.is_some(), UserNotRegistered)?;
        try_or!(
            self.appinst.as_ref().unwrap().base() == preparsed.header.link.base(),
            MessageAppInstMismatch(
                self.appinst.as_ref().unwrap().base().to_string(),
                preparsed.header.link.base().to_string()
            )
        )?;
        Ok(())
    }

    pub fn store_psk(&mut self, pskid: PskId, psk: Psk, use_psk: bool) -> Result<()> {
        match &self.appinst {
            Some(appinst) => {
                let pskid_as_identifier = pskid.into();
                if use_psk && self.id().is_psk() {
                    return err(StateStoreFailure);
                }
                if self.key_store.psks().contains_key(&pskid) {
                    return err(PskAlreadyStored);
                }

                self.key_store.insert_psk(pskid_as_identifier, psk)?;
                self.key_store.cursors_mut().insert(
                    pskid_as_identifier,
                    Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM),
                );
                if use_psk {
                    self.user_id.id = pskid_as_identifier
                }
                Ok(())
            }
            None => err(UserNotRegistered),
        }
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> Result<()> {
        match self.key_store.psks().contains_key(&pskid) {
            true => {
                self.key_store.remove(&pskid.into());
                Ok(())
            }
            false => err(UserNotRegistered),
        }
    }

    /// Generate the link of a message
    ///
    /// The link is generated from the link of the last message sent by the publishing user and its sequence number
    ///
    /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
    pub fn gen_link<I>(&self, id: I, last_link: &Link::Rel, current_seq_no: u32) -> Cursor<Link>
    where
        I: AsRef<[u8]>,
    {
        let new_link = self
            .link_gen
            .link_from(id, Cursor::new_at(last_link, 0, current_seq_no));
        Cursor::new_at(new_link, 0, current_seq_no)
    }

    /// Generate the link of a sequence message of a user given the previous link of its referred message
    ///
    /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
    pub fn gen_seq_link<I>(&self, id: I, previous_link: &Link::Rel) -> Cursor<Link>
    where
        I: AsRef<[u8]>,
    {
        self.gen_link(id, previous_link, SEQ_MESSAGE_NUM)
    }

    /// Generate the next batch of message links to poll
    ///
    /// Given the set of users registered as participants of the channel and their current registered
    /// sequencing position, this method generates a set of new links to poll for new messages
    /// (one for each user, represented by its [`Identifier`]).
    ///
    /// Keep in mind that in multi-branch channels, the link returned corresponds to the next sequence message.
    ///
    /// The link is returned in a [`Cursor<Link>`] to carry over its sequencing information
    pub fn gen_next_msg_links(&self) -> Vec<(Identifier, Cursor<Link>)> {
        // TODO: Turn it into iterator.
        let mut ids = Vec::new();

        // TODO: Do the same for self.user_id.id
        for (id, cursor) in self.key_store.iter() {
            if self.is_multi_branching() {
                ids.push((*id, self.gen_seq_link(&id, &cursor.link)));
            } else {
                ids.push((*id, self.gen_link(&id, &cursor.link, cursor.seq_no)));
            }
        }
        ids
    }

    pub fn store_state(&mut self, id: Identifier, link: Link::Rel) -> Result<()> {
        if let Some(cursor) = self.key_store.cursors_mut().get_mut(&id) {
            cursor.link = link;
            cursor.next_seq();
        }
        Ok(())
    }

    pub fn store_state_for_all(&mut self, link: <Link as HasLink>::Rel, seq_no: u32) -> Result<()> {
        if &seq_no > self.seq_no().as_ref().unwrap_or(&0) {
            self.key_store
                .cursors_mut()
                .insert(self.user_id.id, Cursor::new_at(link.clone(), 0, seq_no));
            for (_pk, cursor) in self.key_store.iter_mut() {
                cursor.link = link.clone();
                cursor.seq_no = seq_no;
            }
        }
        Ok(())
    }

    pub fn fetch_state(&self) -> Result<Vec<(Identifier, Cursor<Link>)>> {
        let mut state = Vec::new();
        try_or!(self.appinst.is_some(), UserNotRegistered)?;

        for (
            pk,
            Cursor {
                link,
                branch_no,
                seq_no,
            },
        ) in self.key_store.iter()
        {
            let link = Link::from_base_rel(self.appinst.as_ref().unwrap().base(), link);
            state.push((*pk, Cursor::new_at(link, *branch_no, *seq_no)))
        }
        Ok(state)
    }

    /// Fetch the anchor message from the user instance (if it exists). - For use in single depth.
    pub fn fetch_anchor(&self) -> Result<&Cursor<Link>> {
        match &self.anchor {
            Some(anchor) => Ok(anchor),
            None => err(UserNotRegistered),
        }
    }
}

#[async_trait(?Send)]
impl<F, Link, LG, LS, Keys> ContentSizeof<F> for User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
    Link::Base: Eq + ToString,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    LS::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<Link::Rel>, F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.mask(<&NBytes<U32>>::from(&self.user_id.sig_sk()?.to_bytes()[..]))?
            .absorb(Uint8(self.flags))?
            .absorb(<&Bytes>::from(&self.message_encoding))?
            .absorb(Uint64(self.uniform_payload_length as u64))?;

        let oneof_appinst = Uint8(if self.appinst.is_some() { 1 } else { 0 });
        ctx.absorb(oneof_appinst)?;
        if let Some(ref appinst) = self.appinst {
            ctx.absorb(<&Fallback<Link>>::from(appinst))?;
        }

        let oneof_author_id = Uint8(if self.author_id.is_some() { 1 } else { 0 });
        ctx.absorb(oneof_author_id)?;
        if let Some(ref author_id) = self.author_id {
            author_id.sizeof(ctx).await?;
        }

        let repeated_links = Size(self.link_store.len());
        let keys = self.key_store.iter();
        let repeated_keys = Size(keys.len());

        ctx.absorb(repeated_links)?;
        for (link, (s, info)) in self.link_store.iter() {
            ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(link))?
                .mask(<&NBytes<F::CapacitySize>>::from(s.arr()))?
                .absorb(<&Fallback<<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info>>::from(
                    info,
                ))?;
        }

        ctx.absorb(repeated_keys)?;
        for (id, cursor) in keys {
            let ctx = (*id).sizeof(ctx).await?;
            ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(&cursor.link))?
                .absorb(Uint32(cursor.branch_no))?
                .absorb(Uint32(cursor.seq_no))?;
        }
        ctx.commit()?.squeeze(Mac(32))?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<F, Link, Store, LG, LS, Keys> ContentWrap<F, Store> for User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
    Link::Base: Eq + ToString,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, Link::Rel>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    LS::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<Link::Rel>, F>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.mask(<&NBytes<U32>>::from(&self.user_id.sig_sk()?.to_bytes()[..]))?
            .absorb(Uint8(self.flags))?
            .absorb(<&Bytes>::from(&self.message_encoding))?
            .absorb(Uint64(self.uniform_payload_length as u64))?;

        let oneof_appinst = Uint8(if self.appinst.is_some() { 1 } else { 0 });
        ctx.absorb(oneof_appinst)?;
        if let Some(ref appinst) = self.appinst {
            ctx.absorb(<&Fallback<Link>>::from(appinst))?;
        }

        let oneof_author_id = Uint8(if self.author_id.is_some() { 1 } else { 0 });
        ctx.absorb(oneof_author_id)?;
        if let Some(ref author_id) = self.author_id {
            author_id.wrap(store, ctx).await?;
        }

        let repeated_links = Size(self.link_store.len());
        let keys = self.key_store.iter();
        let repeated_keys = Size(keys.len());

        ctx.absorb(repeated_links)?;
        for (link, (s, info)) in self.link_store.iter() {
            ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(link))?
                .mask(<&NBytes<F::CapacitySize>>::from(s.arr()))?
                .absorb(<&Fallback<<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info>>::from(
                    info,
                ))?;
        }

        ctx.absorb(repeated_keys)?;
        for (id, cursor) in keys {
            let ctx = id.clone().wrap(store.borrow(), ctx.borrow_mut()).await?;
            ctx.absorb(<&Fallback<<Link as HasLink>::Rel>>::from(&cursor.borrow().link))?
                .absorb(Uint32(cursor.branch_no))?
                .absorb(Uint32(cursor.seq_no))?;
        }
        ctx.commit()?.squeeze(Mac(32))?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<F, Link, Store, LG, LS, Keys> ContentUnwrap<F, Store> for User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, Link::Rel>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    LS::Info: Default + AbsorbFallback<F>,
    Keys: KeyStore<Cursor<Link::Rel>, F> + Default,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut sig_sk_bytes = NBytes::<U32>::default();
        let mut flags = Uint8(0);
        let mut message_encoding = Bytes::new();
        let mut uniform_payload_length = Uint64(0);
        ctx.mask(&mut sig_sk_bytes)?
            .absorb(&mut flags)?
            .absorb(&mut message_encoding)?
            .absorb(&mut uniform_payload_length)?;

        let mut oneof_appinst = Uint8(0);
        ctx.absorb(&mut oneof_appinst)?
            .guard(oneof_appinst.0 < 2, AppInstRecoveryFailure(oneof_appinst.0))?;

        let appinst = if oneof_appinst.0 == 1 {
            let mut appinst = Link::default();
            ctx.absorb(<&mut Fallback<Link>>::from(&mut appinst))?;
            Some(appinst)
        } else {
            None
        };

        let mut oneof_author_id = Uint8(0);
        ctx.absorb(&mut oneof_author_id)?
            .guard(oneof_author_id.0 < 2, AuthorSigPkRecoveryFailure(oneof_author_id.0))?;

        let author_id = if oneof_author_id.0 == 1 {
            let mut author_id = Identifier::default();
            author_id.unwrap(store, ctx).await?;
            Some(author_id)
        } else {
            None
        };

        let mut repeated_links = Size(0);
        let mut link_store = LS::default();

        ctx.absorb(&mut repeated_links)?;
        for _ in 0..repeated_links.0 {
            let mut link = Fallback(<Link as HasLink>::Rel::default());
            let mut s = NBytes::<F::CapacitySize>::default();
            let mut info = Fallback(<LS as LinkStore<F, <Link as HasLink>::Rel>>::Info::default());
            ctx.absorb(&mut link)?.mask(&mut s)?.absorb(&mut info)?;
            let a: GenericArray<u8, F::CapacitySize> = s.into();
            link_store.insert(&link.0, Inner::<F>::from(a), info.0)?;
        }

        let mut repeated_keys = Size(0);
        let mut key_store = Keys::default();
        ctx.absorb(&mut repeated_keys)?;
        for _ in 0..repeated_keys.0 {
            let mut link = Fallback(<Link as HasLink>::Rel::default());
            let mut branch_no = Uint32(0);
            let mut seq_no = Uint32(0);
            let (id, ctx) = Identifier::unwrap_new(store, ctx).await?;
            ctx.absorb(&mut link)?.absorb(&mut branch_no)?.absorb(&mut seq_no)?;
            key_store
                .cursors_mut()
                .insert(id, Cursor::new_at(link.0, branch_no.0, seq_no.0));
        }

        ctx.commit()?.squeeze(Mac(32))?;

        let sig_sk = ed25519::SecretKey::from_bytes(<[u8; 32]>::try_from(sig_sk_bytes.as_ref())?);
        let sig_pk = sig_sk.public_key();

        self.user_id = UserIdentity::from((sig_sk, sig_pk));
        self.link_store = link_store;
        self.key_store = key_store;
        self.author_id = author_id;
        if let Some(ref seed) = appinst {
            self.link_gen.reset(seed.clone());
        }
        self.appinst = appinst;
        self.flags = flags.0;
        self.message_encoding = message_encoding.0;
        self.uniform_payload_length = uniform_payload_length.0 as usize;
        Ok(ctx)
    }
}

impl<F, Link, LG, LS, Keys> User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
    Link::Base: Eq + ToString,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    LS::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<Link::Rel>, F>,
{
    pub async fn export(&self, flag: u8, pwd: &str) -> Result<Vec<u8>> {
        const VERSION: u8 = 0;
        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.absorb(Uint8(VERSION))?.absorb(Uint8(flag))?;
            self.sizeof(&mut ctx).await?;
            ctx.size()
        };

        let mut buf = vec![0; buf_size];

        {
            let mut ctx = wrap::Context::new(&mut buf[..]);
            let prng = prng::from_seed::<F>("IOTA Streams Channels app", pwd);
            let key = NBytes::<U32>(prng.gen_arr("user export key"));
            ctx.absorb(Uint8(VERSION))?
                .absorb(Uint8(flag))?
                .absorb(External(&key))?;
            let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
            self.wrap(&store, &mut ctx).await?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
        }

        Ok(buf)
    }
}

impl<F, Link, LG, LS, Keys> User<F, Link, LG, LS, Keys>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + AbsorbFallback<F>,
    Link::Rel: Eq + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, Link::Rel> + Default,
    LS::Info: Default + AbsorbFallback<F>,
    Keys: KeyStore<Cursor<Link::Rel>, F> + Default,
{
    pub async fn import(bytes: &[u8], flag: u8, pwd: &str) -> Result<Self> {
        const VERSION: u8 = 0;

        let mut ctx = unwrap::Context::new(bytes);
        let prng = prng::from_seed::<F>("IOTA Streams Channels app", pwd);
        let key = NBytes::<U32>(prng.gen_arr("user export key"));
        let mut version = Uint8(0);
        let mut flag2 = Uint8(0);
        ctx.absorb(&mut version)?
            .guard(version.0 == VERSION, UserVersionRecoveryFailure(VERSION, version.0))?
            .absorb(&mut flag2)?
            .guard(flag2.0 == flag, UserFlagRecoveryFailure(flag, flag2.0))?
            .absorb(External(&key))?;

        let mut user = User::default();
        let store = EmptyLinkStore::<F, Link::Rel, ()>::default();
        user.unwrap(&store, &mut ctx).await?;
        try_or!(ctx.stream.is_empty(), InputStreamNotFullyConsumed(ctx.stream.len()))?;
        Ok(user)
    }
}

// Newtype wrapper around KeyStore reference to be able to implement Lookup on it
// Direct implementation is not possible due to KeyStore trait having type parameters itself
pub struct KeysLookup<'a, F, Link, KStore>(&'a KStore, PhantomData<F>, PhantomData<Link>)
where
    F: PRP,
    Link: HasLink,
    KStore: KeyStore<Cursor<Link::Rel>, F>;

impl<'a, F, Link, KStore> KeysLookup<'a, F, Link, KStore>
where
    F: PRP,
    Link: HasLink,
    KStore: KeyStore<Cursor<Link::Rel>, F>,
{
    fn new(key_store: &'a KStore) -> Self {
        Self(key_store, PhantomData, PhantomData)
    }
}

impl<F, Link, KStore> Lookup<&Identifier, psk::Psk> for KeysLookup<'_, F, Link, KStore>
where
    F: PRP,
    Link: HasLink,
    KStore: KeyStore<Cursor<Link::Rel>, F>,
{
    fn lookup(&self, id: &Identifier) -> Option<psk::Psk> {
        if let Identifier::PskId(pskid) = id {
            self.0.psks().get(pskid).map(|psk| *psk)
        } else {
            None
        }
    }
}

pub struct OwnKeys<'a, F>(&'a UserIdentity<F>);

impl<'a, F: PRP> Lookup<&Identifier, x25519::SecretKey> for OwnKeys<'a, F> {
    fn lookup(&self, id: &Identifier) -> Option<x25519::SecretKey> {
        let Self(UserIdentity { id: self_id, .. }) = self;
        if id == self_id {
            self.0.ke_kp().map_or(None, |(secret, _public)| Some(secret))
        } else {
            None
        }
    }
}
