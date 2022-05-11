use core::{
    borrow::Borrow,
    fmt::{
        self,
        Debug,
    },
    marker::PhantomData,
};

use iota_streams_app::{
    identifier::Identifier,
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
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
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
use core::borrow::BorrowMut;

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

    /// Own Ed25519 private key.
    pub(crate) sig_kp: ed25519::Keypair,

    /// Own x25519 key pair corresponding to Ed25519 keypair.
    pub(crate) ke_kp: (x25519::StaticSecret, x25519::PublicKey),

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    pub(crate) key_store: Keys,

    /// Author's Ed25519 public key.
    pub(crate) author_sig_pk: Option<ed25519::PublicKey>,

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
        let sig_kp = ed25519::Keypair {
            secret: ed25519::SecretKey::from_bytes(&[0; ed25519::SECRET_KEY_LENGTH]).unwrap(),
            public: ed25519::PublicKey::default(),
        };
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        Self {
            _phantom: PhantomData,
            sig_kp,
            ke_kp,

            key_store: Keys::default(),
            author_sig_pk: None,
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
    Link: HasLink + AbsorbExternalFallback<F> + Default + Debug,
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F>,
{
    /// Create a new User and generate Ed25519 key pair and corresponding X25519 key pair.
    pub fn gen(
        prng: prng::Prng<F>,
        nonce: Vec<u8>,
        channel_type: ChannelType,
        message_encoding: Vec<u8>,
        uniform_payload_length: usize,
    ) -> Self {
        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng, nonce));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        let flags: u8 = match channel_type {
            ChannelType::SingleBranch => 0,
            ChannelType::MultiBranch => 1,
            ChannelType::SingleDepth => 2,
        };

        Self {
            _phantom: PhantomData,
            sig_kp,
            ke_kp,

            key_store: Keys::default(),
            author_sig_pk: None,
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
        self.link_gen.gen(&self.sig_kp.public, channel_idx);
        let appinst = self.link_gen.get();

        let identifier = self.sig_kp.public.into();
        self.key_store
            .insert_cursor(identifier, Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM))?;
        self.author_sig_pk = Some(self.sig_kp.public);
        self.anchor = Some(Cursor::new_at(appinst.clone(), 0, INIT_MESSAGE_NUM));
        self.appinst = Some(appinst);
        Ok(())
    }

    /// Channel Author's signature public key
    pub fn author_public_key(&self) -> Option<&ed25519::PublicKey> {
        self.author_sig_pk.as_ref()
    }

    /// Reset link store and key store to original state
    pub fn reset_state(&mut self) -> Result<()> {
        match &self.appinst {
            Some(appinst) => {
                let mut key_store = Keys::default();
                for (id, _cursor) in self.key_store.iter() {
                    key_store.insert_cursor(*id, Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM))?;
                }
                self.key_store = key_store;

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
            .with_identifier(&self.sig_kp.public.into());
        let content = announce::ContentWrap::new(&self.sig_kp, self.flags);
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
                UserAlreadyRegistered(hex::encode(self.sig_kp.public), appinst.base().to_string())
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
        // TODO: check commit after message is done / before joined

        // TODO: Verify trust to Author's public key?
        // At the moment the Author is trusted unconditionally.

        // TODO: Verify appinst (address) == public key.
        // At the moment the Author is free to choose any address, not tied to PK.

        let cursor = Cursor::new_at(link.rel().clone(), 0, INIT_MESSAGE_NUM);
        self.key_store
            .insert_cursor(Identifier::EdPubKey(content.sig_pk.into()), cursor.clone())?;
        self.key_store
            .insert_cursor(Identifier::EdPubKey(self.sig_kp.public.into()), cursor)?;
        // Reset link_gen
        self.link_gen.reset(link.clone());
        self.anchor = Some(Cursor::new_at(link.clone(), 0, INIT_MESSAGE_NUM));
        self.appinst = Some(link);
        self.author_sig_pk = Some(content.sig_pk);
        self.flags = content.flags.0;
        Ok(())
    }

    /// Prepare Subscribe message.
    pub fn prepare_subscribe<'a>(
        &'a self,
        link_to: &'a Link,
    ) -> Result<PreparedMessage<F, Link, subscribe::ContentWrap<'a, F, Link>>> {
        if let Some(author_sig_pk) = &self.author_sig_pk {
            let identifier = Identifier::EdPubKey(ed25519::PublicKeyWrap(*author_sig_pk));
            if let Some(author_ke_pk) = self.key_store.get_ke_pk(&identifier) {
                let msg_cursor = self.gen_link(&self.sig_kp.public, link_to.rel(), SUB_MESSAGE_NUM);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(SUBSCRIBE)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.sig_kp.public.into());
                let unsubscribe_key = NBytes::from(prng::random_key());
                let content = subscribe::ContentWrap {
                    link: link_to.rel(),
                    unsubscribe_key,
                    subscriber_sig_kp: &self.sig_kp,
                    author_ke_pk,
                    _phantom: PhantomData,
                };
                Ok(PreparedMessage::new(header, content))
            } else {
                err!(AuthorExchangeKeyNotFound)
            }
        } else {
            err!(AuthorSigKeyNotFound)
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
        author_ke_pk: &'a x25519::StaticSecret,
    ) -> Result<UnwrappedMessage<F, Link, subscribe::ContentUnwrap<'a, F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = subscribe::ContentUnwrap::new(author_ke_pk)?;
        preparsed.unwrap(&self.link_store, content).await
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub async fn handle_subscribe(&mut self, msg: &BinaryMessage<Link>, info: LS::Info) -> Result<()> {
        let preparsed = msg.parse_header().await?;
        // TODO: check content type

        let content = self
            // We need to borrow self.ke_kp.0 at this scope
            // to leverage https://doc.rust-lang.org/nomicon/borrow-splitting.html
            .unwrap_subscribe(preparsed, &self.ke_kp.0)
            .await?
            .commit(&mut self.link_store, info)?;
        // TODO: trust content.subscriber_sig_pk
        // TODO: remove unused unsubscribe_key because it is unnecessary for verification anymore
        let subscriber_sig_pk = content.subscriber_sig_pk;
        self.insert_subscriber(subscriber_sig_pk)
    }

    pub fn insert_subscriber(&mut self, pk: ed25519::PublicKey) -> Result<()> {
        match (!self.key_store.contains(&pk.into()), &self.appinst) {
            (_, None) => err!(UserNotRegistered),
            (true, Some(ref_link)) => self
                .key_store
                .insert_cursor(pk.into(), Cursor::new_at(ref_link.rel().clone(), 0, INIT_MESSAGE_NUM)),
            (false, Some(ref_link)) => err!(UserAlreadyRegistered(
                hex::encode(pk.as_bytes()),
                ref_link.base().to_string()
            )),
        }
    }

    /// Prepare Subscribe message.
    pub fn prepare_unsubscribe<'a>(
        &'a self,
        link_to: &'a Link,
    ) -> Result<PreparedMessage<F, Link, unsubscribe::ContentWrap<'a, F, Link>>> {
        match self.get_seq_no() {
            Some(seq_no) => {
                let msg_link = self
                    .link_gen
                    .link_from(self.sig_kp.public, Cursor::new_at(link_to.rel(), 0, seq_no));
                let header = HDF::new(msg_link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(UNSUBSCRIBE)?
                    .with_payload_length(1)?
                    .with_seq_num(seq_no)
                    .with_identifier(&self.sig_kp.public.into());
                let content = unsubscribe::ContentWrap {
                    link: link_to.rel(),
                    sig_kp: &self.sig_kp,
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
        self.remove_subscriber(content.sig_pk)
    }

    pub fn remove_subscriber(&mut self, pk: ed25519::PublicKey) -> Result<()> {
        let id = pk.into();
        match self.key_store.contains(&id) {
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
        keys: Vec<(&'a Identifier, Vec<u8>)>,
    ) -> Result<PreparedMessage<F, Link, keyload::ContentWrap<'a, F, Link>>> {
        let nonce = NBytes::from(prng::random_nonce());
        let key = NBytes::from(prng::random_key());
        let content = keyload::ContentWrap {
            link: link_to,
            nonce,
            key,
            keys,
            sig_kp: &self.sig_kp,
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
        match self.get_seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.sig_kp.public, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(KEYLOAD)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.sig_kp.public.into());
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
        match self.get_seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.sig_kp.public, link_to.rel(), seq_no);
                let header = hdf::HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(KEYLOAD)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.sig_kp.public.into());
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
        own_keys: OwnKeys<'a>,
        author_sig_pk: Option<&'a ed25519::PublicKey>,
    ) -> Result<
        UnwrappedMessage<F, Link, keyload::ContentUnwrap<'a, F, Link, KeysLookup<'a, F, Link, Keys>, OwnKeys<'a>>>,
    > {
        self.ensure_appinst(&preparsed)?;
        if let Some(author_sig_pk) = author_sig_pk {
            let content = keyload::ContentUnwrap::new(keys_lookup, own_keys, author_sig_pk);
            preparsed.unwrap(&self.link_store, content).await
        } else {
            err!(AuthorSigKeyNotFound)
        }
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or Ed25519 private key (if any).
    pub async fn handle_keyload(
        &mut self,
        msg: &BinaryMessage<Link>,
        info: LS::Info,
    ) -> Result<GenericMessage<Link, bool>> {
        let preparsed = msg.parse_header().await?;
        let prev_link = Link::try_from_bytes(&preparsed.header.previous_msg_link.0)?;
        let seq_no = preparsed.header.seq_num;
        // We need to borrow self.key_store, self.sig_kp and self.ke_kp at this scope
        // to leverage https://doc.rust-lang.org/nomicon/borrow-splitting.html
        let keys_lookup = KeysLookup::new(&self.key_store);
        let own_keys = OwnKeys(&self.sig_kp, &self.ke_kp);
        let unwrapped = self
            .unwrap_keyload(preparsed, keys_lookup, own_keys, self.author_sig_pk.as_ref())
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
                if !self.key_store.contains(&identifier) {
                    // Store at state 2 since 0 and 1 are reserved states
                    self.key_store
                        .insert_cursor(identifier, Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM))?;
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

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(
        &'a self,
        link_to: &'a Link,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<F, Link, signed_packet::ContentWrap<'a, F, Link>>> {
        if self.use_psk {
            return err(MessageBuildFailure);
        }
        match self.get_seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(self.sig_kp.public, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(SIGNED_PACKET)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&self.sig_kp.public.into());
                let content = signed_packet::ContentWrap {
                    link: link_to.rel(),
                    public_payload,
                    masked_payload,
                    sig_kp: &self.sig_kp,
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
    ) -> Result<GenericMessage<Link, (ed25519::PublicKey, Bytes, Bytes)>> {
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

        let body = (content.sig_pk, content.public_payload, content.masked_payload);
        Ok(GenericMessage::new(msg.link.clone(), prev_link, body))
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a self,
        link_to: &'a Link,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<F, Link, tagged_packet::ContentWrap<'a, F, Link>>> {
        let identifier = self.get_identifier()?;
        match self.get_seq_no() {
            Some(seq_no) => {
                let msg_cursor = self.gen_link(identifier, link_to.rel(), seq_no);
                let header = HDF::new(msg_cursor.link)
                    .with_previous_msg_link(Bytes(link_to.to_bytes()))
                    .with_content_type(TAGGED_PACKET)?
                    .with_payload_length(1)?
                    .with_seq_num(msg_cursor.seq_no)
                    .with_identifier(&identifier);
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

    fn get_identifier(&self) -> Result<Identifier> {
        if self.use_psk {
            match self.key_store.get_next_pskid() {
                Some(pskid) => Ok(*pskid),
                None => err(MessageBuildFailure),
            }
        } else {
            Ok(self.sig_kp.public.into())
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
        let identifier = self.get_identifier()?;
        match self.key_store.get(&identifier) {
            Some(original_cursor) => {
                if (self.flags & FLAG_BRANCHING_MASK) != 0 {
                    let previous_msg_link =
                        Link::from_base_rel(self.appinst.as_ref().unwrap().base(), &original_cursor.link);
                    let seq_msg_cursor = self.gen_seq_link(identifier, &original_cursor.link);
                    let header = HDF::new(seq_msg_cursor.link)
                        .with_previous_msg_link(Bytes(previous_msg_link.to_bytes()))
                        .with_content_type(SEQUENCE)?
                        .with_payload_length(1)?
                        .with_seq_num(seq_msg_cursor.seq_no)
                        .with_identifier(&identifier);

                    let content = sequence::ContentWrap::<Link> {
                        link: &original_cursor.link,
                        id: identifier,
                        seq_num: original_cursor.get_seq_num(),
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
                    let full_cursor = self.gen_link(self.sig_kp.public, ref_link, original_cursor.seq_no);
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
        self.key_store
            .insert_cursor(Identifier::EdPubKey(self.sig_kp.public.into()), cursor)?;
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
    pub fn get_seq_no(&self) -> Option<u32> {
        self.key_store
            .get(&Identifier::EdPubKey(self.sig_kp.public.into()))
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
                if use_psk && self.key_store.get_next_pskid() != None {
                    return err(StateStoreFailure);
                }

                if !self.key_store.contains(&pskid.into()) {
                    self.key_store.insert_psk(
                        pskid.into(),
                        Some(psk),
                        Cursor::new_at(appinst.rel().clone(), 0, INIT_MESSAGE_NUM),
                    )?;
                    self.use_psk = use_psk;
                    Ok(())
                } else {
                    err(PskAlreadyStored)
                }
            }
            None => err(UserNotRegistered),
        }
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> Result<()> {
        let id = pskid.into();
        match self.key_store.contains(&id) {
            true => {
                self.key_store.remove(&id);
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

        // TODO: Do the same for self.sig_kp.public
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
        if let Some(cursor) = self.key_store.get_mut(&id) {
            cursor.link = link;
            cursor.next_seq();
        }
        Ok(())
    }

    pub fn store_state_for_all(&mut self, link: <Link as HasLink>::Rel, seq_no: u32) -> Result<()> {
        if &seq_no > self.get_seq_no().as_ref().unwrap_or(&0) {
            self.key_store.insert_cursor(
                Identifier::EdPubKey(self.sig_kp.public.into()),
                Cursor::new_at(link.clone(), 0, seq_no),
            )?;
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
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.mask(<&NBytes<U32>>::from(&self.sig_kp.secret.as_bytes()[..]))?
            .absorb(Uint8(self.flags))?
            .absorb(<&Bytes>::from(&self.message_encoding))?
            .absorb(Uint64(self.uniform_payload_length as u64))?;

        let oneof_appinst = Uint8(if self.appinst.is_some() { 1 } else { 0 });
        ctx.absorb(&oneof_appinst)?;
        if let Some(ref appinst) = self.appinst {
            ctx.absorb(<&Fallback<Link>>::from(appinst))?;
        }

        let oneof_author_sig_pk = Uint8(if self.author_sig_pk.is_some() { 1 } else { 0 });
        ctx.absorb(&oneof_author_sig_pk)?;
        if let Some(ref author_sig_pk) = self.author_sig_pk {
            ctx.absorb(author_sig_pk)?;
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
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.mask(<&NBytes<U32>>::from(&self.sig_kp.secret.as_bytes()[..]))?
            .absorb(Uint8(self.flags))?
            .absorb(<&Bytes>::from(&self.message_encoding))?
            .absorb(Uint64(self.uniform_payload_length as u64))?;

        let oneof_appinst = Uint8(if self.appinst.is_some() { 1 } else { 0 });
        ctx.absorb(&oneof_appinst)?;
        if let Some(ref appinst) = self.appinst {
            ctx.absorb(<&Fallback<Link>>::from(appinst))?;
        }

        let oneof_author_sig_pk = Uint8(if self.author_sig_pk.is_some() { 1 } else { 0 });
        ctx.absorb(&oneof_author_sig_pk)?;
        if let Some(ref author_sig_pk) = self.author_sig_pk {
            ctx.absorb(author_sig_pk)?;
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
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info: Default + AbsorbFallback<F>,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F> + Default,
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
        ctx
            //.absorb(&self.sig_kp.public)
            .mask(&mut sig_sk_bytes)?
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

        let mut oneof_author_sig_pk = Uint8(0);
        ctx.absorb(&mut oneof_author_sig_pk)?.guard(
            oneof_author_sig_pk.0 < 2,
            AuthorSigPkRecoveryFailure(oneof_author_sig_pk.0),
        )?;

        let author_sig_pk = if oneof_author_sig_pk.0 == 1 {
            let mut author_sig_pk = ed25519::PublicKey::default();
            ctx.absorb(&mut author_sig_pk)?;
            Some(author_sig_pk)
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
            key_store.insert_cursor(id, Cursor::new_at(link.0, branch_no.0, seq_no.0))?;
        }

        ctx.commit()?.squeeze(Mac(32))?;

        let sig_sk = ed25519::SecretKey::from_bytes(sig_sk_bytes.as_ref()).unwrap();
        let sig_pk = ed25519::PublicKey::from(&sig_sk);
        self.sig_kp = ed25519::Keypair {
            secret: sig_sk,
            public: sig_pk,
        };
        self.ke_kp = x25519::keypair_from_ed25519(&self.sig_kp);
        self.link_store = link_store;
        self.key_store = key_store;
        self.author_sig_pk = author_sig_pk;
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
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info: AbsorbFallback<F>,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F>,
{
    pub async fn export(&self, flag: u8, pwd: &str) -> Result<Vec<u8>> {
        const VERSION: u8 = 0;
        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.absorb(Uint8(VERSION))?.absorb(Uint8(flag))?;
            self.sizeof(&mut ctx).await?;
            ctx.get_size()
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
    <Link as HasLink>::Base: Eq + fmt::Debug + fmt::Display,
    <Link as HasLink>::Rel: Eq + fmt::Debug + SkipFallback<F> + AbsorbFallback<F>,
    LG: LinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info: Default + AbsorbFallback<F>,
    Keys: KeyStore<Cursor<<Link as HasLink>::Rel>, F> + Default,
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
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
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
        self.0.get_psk(id)
    }
}

pub struct OwnKeys<'a>(&'a ed25519::Keypair, &'a (x25519::StaticSecret, x25519::PublicKey));

impl<'a> Lookup<&Identifier, &'a x25519::StaticSecret> for OwnKeys<'a> {
    fn lookup(&self, id: &Identifier) -> Option<&'a x25519::StaticSecret> {
        let Self(ed25519::Keypair { public: sig_pk, .. }, (ke_sk, _)) = self;
        match id.get_pk() {
            Some(pk_id) => {
                if sig_pk == pk_id {
                    Some(ke_sk)
                } else {
                    None
                }
            }
            None => None,
        }
    }
}
