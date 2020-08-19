use anyhow::{
    bail,
    ensure,
    Result,
};
use core::{
    cell::RefCell,
    fmt::Debug,
};

use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    prng,
    psk,
    sponge::spongos,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

use iota_streams_app::message::{
    header::Header,
    *,
};
use iota_streams_protobuf3::types::*;

use super::*;
use crate::message::*;

const SUB_MESSAGE_NUM: usize = 0;
const SEQ_MESSAGE_NUM: usize = 1;

/// Generic Channel Subscriber type parametrised by the type of links, link store and
/// link generator.
///
/// `Link` type defines, well, type of links used by transport layer to identify messages.
/// For example, for HTTP it can be URL, and for the Tangle it's a pair `address`+`tag`
/// transaction fields (see `TangleAddress` type). `Link` type must implement `HasLink`
/// and `AbsorbExternalFallback` traits.
///
/// `Store` type abstracts over different kinds of link storages. Link storage is simply
/// a map from link to a spongos state and associated info corresponding to the message
/// referred by the link. `Store` must implement `LinkStore<Link::Rel>` trait as
/// it's only allowed to link messages within the same channel instance.
///
/// `LinkGen` is a helper tool for deriving links for new messages. It maintains a
/// mutable state and can derive link pseudorandomly.
pub struct SubscriberT<F, Link, Store, LinkGen> {
    /// PRNG used for Spongos key generation, etc.
    #[allow(dead_code)]
    prng: prng::Prng<F>,

    /// Own Ed25519 private key.
    pub(crate) sig_kp: ed25519::Keypair,

    /// Own x25519 key pair corresponding to Ed25519 keypair.
    pub(crate) ke_kp: (x25519::StaticSecret, x25519::PublicKey),

    /// Own optional pre-shared key.
    pub(crate) opt_psk: Option<(psk::PskId, psk::Psk)>,

    /// Subscribers' trusted X25519 public keys.
    pub ke_pks: x25519::Pks,

    /// Author's Ed25519 public key.
    pub(crate) author_sig_pk: Option<ed25519::PublicKey>,

    /// Author's x25519 public key corresponding to Ed25519 keypair.
    pub(crate) author_ke_pk: Option<x25519::PublicKeyWrap>,

    /// Address of the Announce message or nothing if Subscriber is not registered to
    /// the channel instance.
    pub(crate) appinst: Option<Link>,

    /// Link store.
    store: RefCell<Store>,

    /// Link generator.
    pub(crate) link_gen: LinkGen,

    /// u8 indicating if multi_branching is used (0 = false, 1 = true)
    pub multi_branching: u8,

    /// Mapping of publisher id to sequence state
    pub(crate) seq_states: HashMap<Vec<u8>, (Link, usize)>,
}

impl<F, Link, Store, LinkGen> SubscriberT<F, Link, Store, LinkGen>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + Default + Clone + Eq,
    <Link as HasLink>::Base: Eq + Debug,
    <Link as HasLink>::Rel: Eq + Debug + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LinkGen: ChannelLinkGenerator<Link>,
{
    /// Create a new Subscriber.
    pub fn gen(store: Store, link_gen: LinkGen, prng: prng::Prng<F>, nonce: Vec<u8>) -> Self {
        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng.clone(), nonce.clone()));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        Self {
            prng: prng,
            sig_kp,
            ke_kp,
            opt_psk: None,

            appinst: None,
            author_sig_pk: None,
            author_ke_pk: None,
            ke_pks: x25519::Pks::new(),

            store: RefCell::new(store),
            link_gen: link_gen,
            multi_branching: 0,
            seq_states: HashMap::new(),
        }
    }

    fn ensure_appinst<'a>(&self, preparsed: &PreparsedMessage<'a, F, Link>) -> Result<()> {
        ensure!(self.appinst.is_some(), "Subscriber is not subscribed to a channel.");
        ensure!(
            self.appinst.as_ref().unwrap().base() == preparsed.header.link.base(),
            "Bad message application instance."
        );
        Ok(())
    }

    fn do_prepare_keyload<'a, Psks, KePks>(
        &'a self,
        header: Header<Link>,
        link_to: &'a <Link as HasLink>::Rel,
        psks: Psks,
        ke_pks: KePks,
    ) -> Result<PreparedMessage<'a, F, Link, Store, keyload::ContentWrap<'a, F, Link, Psks, KePks>>>
    where
        Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
        KePks: Clone + ExactSizeIterator<Item = x25519::IPk<'a>>,
    {
        let nonce = NBytes(prng::random_nonce(spongos::Spongos::<F>::NONCE_SIZE));
        let key = NBytes(prng::random_key(spongos::Spongos::<F>::KEY_SIZE));
        let content = keyload::ContentWrap {
            link: link_to,
            nonce: nonce,
            key: key,
            psks: psks,
            ke_pks: ke_pks,
            _phantom: core::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    pub fn prepare_keyload<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Result<
        PreparedMessage<
            'a,
            F,
            Link,
            Store,
            keyload::ContentWrap<
                'a,
                F,
                Link,
                core::option::IntoIter<psk::IPsk<'a>>,
                core::option::IntoIter<x25519::IPk<'a>>,
            >,
        >,
    > {
        let header = self.link_gen.header_from(
            link_to,
            self.ke_kp.1,
            self.multi_branching,
            self.get_seq_num(),
            keyload::TYPE,
        );
        self.do_prepare_keyload(
            header,
            link_to,
            self.opt_psk.as_ref().map(|(pskid, psk)| (pskid, psk)).into_iter(),
            self.author_ke_pk.as_ref().into_iter(),
        )
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_keyload(link_to)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    pub fn prepare_sequence<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        seq_num: usize,
        ref_link: NBytes,
    ) -> Result<PreparedMessage<'a, F, Link, Store, sequence::ContentWrap<'a, Link>>> {
        let header = self.link_gen.header_from(
            link_to,
            self.ke_kp.1,
            self.multi_branching,
            SEQ_MESSAGE_NUM,
            sequence::TYPE,
        );

        let content = sequence::ContentWrap {
            link: link_to,
            pubkey: &self.ke_kp.1,
            seq_num: seq_num,
            ref_link: ref_link,
        };

        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Send sequence message to show referenced message
    pub fn sequence<'a>(
        &mut self,
        ref_link: Vec<u8>,
        seq_link: <Link as HasLink>::Rel,
        seq_num: usize,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_sequence(&seq_link, seq_num, NBytes(ref_link))?.wrap()?;

        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<'a, F, Link, Store, tagged_packet::ContentWrap<'a, F, Link>>> {
        let header = self.link_gen.header_from(
            link_to,
            self.ke_kp.1,
            self.multi_branching,
            self.get_seq_num(),
            tagged_packet::TYPE,
        );
        let content = tagged_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            _phantom: core::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Create a tagged (ie. MACed) message with public and masked payload.
    /// Tagged messages must be linked to a secret spongos state, ie. keyload or a message linked to keyload.
    pub fn tag_packet(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        public_payload: &Bytes,
        masked_payload: &Bytes,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self
            .prepare_tagged_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare Subscribe message.
    pub fn prepare_subscribe<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Result<PreparedMessage<'a, F, Link, Store, subscribe::ContentWrap<'a, F, Link>>> {
        if let Some(author_ke_pk) = &self.author_ke_pk {
            let header = self.link_gen.header_from(
                link_to,
                self.ke_kp.1,
                self.multi_branching,
                SUB_MESSAGE_NUM,
                subscribe::TYPE,
            );
            // let nonce = NBytes(prng::random_nonce(spongos::Spongos::<F>::NONCE_SIZE));
            let unsubscribe_key = NBytes(prng::random_key(spongos::Spongos::<F>::KEY_SIZE));
            let content = subscribe::ContentWrap {
                link: link_to,
                unsubscribe_key,
                subscriber_sig_kp: &self.sig_kp,
                author_ke_pk: &author_ke_pk.0,
                _phantom: core::marker::PhantomData,
            };
            Ok(PreparedMessage::new(self.store.borrow(), header, content))
        } else {
            bail!("Subscriber doesn't have channel Author's x25519 public key.");
        }
    }

    /// Subscribe to the channel.
    pub fn subscribe(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_subscribe(link_to)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    // Prepare Unsubscribe message.
    // pub fn prepare_unsubscribe<'a>(
    // &'a mut self,
    // link_to: &'a <Link as HasLink>::Rel,
    // ) -> Result<PreparedMessage<'a, F, Link, Store, unsubscribe::ContentWrap<'a, F, Link>>> {
    // let header = self.link_gen.header_from(link_to, unsubscribe::TYPE);
    // let content = unsubscribe::ContentWrap {
    // link: link_to,
    // _phantom: core::marker::PhantomData,
    // };
    // Ok(PreparedMessage::new(self.store.borrow(), header, content))
    // }
    //
    // Unsubscribe from the channel.
    // pub fn unsubscribe(
    // &mut self,
    // link_to: &<Link as HasLink>::Rel,
    // info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    // ) -> Result<TbinaryMessage<F, Link>> {
    // let wrapped = self.prepare_unsubscribe(link_to)?.wrap()?;
    // wrapped.commit(self.store.borrow_mut(), info)
    // }

    pub fn unwrap_announcement<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, announce::ContentUnwrap<F>>> {
        if let Some(appinst) = &self.appinst {
            ensure!(
                appinst == &preparsed.header.link,
                "Got Announce with address {:?}, but already registered to a channel {:?}",
                preparsed.header.link.base(),
                appinst.base()
            );
        }

        let content = announce::ContentUnwrap::<F>::default();
        let r = preparsed.unwrap(&*self.store.borrow(), content);
        r
    }

    /// Bind Subscriber (or anonymously subscribe) to the channel announced
    /// in the message.
    pub fn handle_announcement<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let unwrapped = self.unwrap_announcement(preparsed)?;
        let link = unwrapped.link.clone();
        let content = unwrapped.commit(self.store.borrow_mut(), info)?;
        // TODO: check commit after message is done / before joined

        // TODO: Verify trust to Author's MSS public key?
        // At the moment the Author is trusted unconditionally.

        // TODO: Verify appinst (address) == MSS public key.
        // At the moment the Author is free to choose any address, not tied to MSS PK.

        self.appinst = Some(link);
        self.author_sig_pk = Some(content.sig_pk);
        self.author_ke_pk = Some(x25519::PublicKeyWrap(content.ke_pk));
        self.ke_pks.insert(x25519::PublicKeyWrap(content.ke_pk));
        self.multi_branching = content.multi_branching;
        Ok(())
    }

    fn lookup_psk<'b>(&'b self, pskid: &psk::PskId) -> Option<&'b psk::Psk> {
        self.opt_psk.as_ref().map_or(
            None,
            |(own_pskid, own_psk)| {
                if pskid == own_pskid {
                    Some(own_psk)
                } else {
                    None
                }
            },
        )
    }

    fn lookup_ke_sk<'b>(&'b self, ke_pk: &x25519::PublicKey) -> Option<&'b x25519::StaticSecret> {
        if (self.ke_kp.1).as_bytes() == ke_pk.as_bytes() {
            Some(&self.ke_kp.0)
        } else {
            None
        }
    }

    pub fn unwrap_keyload<'a, 'b>(
        &'b self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<
        UnwrappedMessage<
            F,
            Link,
            keyload::ContentUnwrap<
                'b,
                F,
                Link,
                Self,
                for<'c> fn(&'c Self, &psk::PskId) -> Option<&'c psk::Psk>,
                for<'c> fn(&'c Self, &x25519::PublicKey) -> Option<&'c x25519::StaticSecret>,
            >,
        >,
    > {
        self.ensure_appinst(&preparsed)?;
        let content = keyload::ContentUnwrap::<
            'b,
            F,
            Link,
            Self,
            for<'c> fn(&'c Self, &psk::PskId) -> Option<&'c psk::Psk>,
            for<'c> fn(&'c Self, &x25519::PublicKey) -> Option<&'c x25519::StaticSecret>,
        >::new(self, Self::lookup_psk, Self::lookup_ke_sk);
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or NTRU private key (if any).
    pub fn handle_keyload<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let content = self.unwrap_keyload(preparsed)?.commit(self.store.borrow_mut(), info)?;
        // Unwrapped nonce and key in content are not used explicitly.
        // The resulting spongos state is joined into a protected message state.
        // Store any unknown publishers
        for pkid in content.ke_pks {
            if !self.seq_states.contains_key(&pkid.0.as_bytes().to_vec()) {
                // Store at state 2 since 0 and 1 are reserved states
                self.ke_pks.insert(pkid.clone());
                self.store_state(pkid.0, self.appinst.clone().unwrap(), 2)
            }
        }

        Ok(())
    }

    pub fn unwrap_signed_packet<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, signed_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = signed_packet::ContentUnwrap::with_sig(self.author_sig_pk.unwrap());
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Verify new Author's MSS public key and update Author's MSS public key.
    pub fn handle_signed_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<(Bytes, Bytes)> {
        // TODO: pass author_pk to unwrap
        let content = self
            .unwrap_signed_packet(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok((content.public_payload, content.masked_payload))
    }

    pub fn unwrap_tagged_packet<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, tagged_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = tagged_packet::ContentUnwrap::new();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_tagged_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<(Bytes, Bytes)> {
        let content = self
            .unwrap_tagged_packet(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok((content.public_payload, content.masked_payload))
    }

    pub fn unwrap_sequence<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, sequence::ContentUnwrap<Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = sequence::ContentUnwrap::default();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    // Fetch unwrapped sequence message to fetch referenced message
    pub fn handle_sequence<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<sequence::ContentUnwrap<Link>> {
        let content = self.unwrap_sequence(preparsed)?.commit(self.store.borrow_mut(), info)?;
        Ok(content)
    }

    pub fn get_branching_flag<'a>(&self) -> &u8 {
        &self.multi_branching
    }

    pub fn gen_msg_id(&mut self, link: &<Link as HasLink>::Rel, pk: x25519::PublicKey, seq: usize) -> Link {
        let multi_branch = self.multi_branching.clone();
        self.link_gen.link_from(link, pk, multi_branch, seq)
    }

    pub fn get_pks(&self) -> x25519::Pks {
        self.ke_pks.clone()
    }

    /// Store the sequence state of a given publisher
    pub fn store_state(&mut self, pubkey: x25519::PublicKey, msg_link: Link, seq_num: usize) {
        self.seq_states.insert(pubkey.as_bytes().to_vec(), (msg_link, seq_num));
    }

    /// Retrieve the sequence state fo a given publisher
    pub fn get_seq_state(&self, pubkey: x25519::PublicKey) -> Result<(Link, usize)> {
        let seq_link = self.seq_states.get(&pubkey.as_bytes().to_vec()).unwrap().0.clone();
        let seq_num = self.seq_states.get(&pubkey.as_bytes().to_vec()).unwrap().1;
        Ok((seq_link, seq_num))
    }

    pub fn get_seq_num(&self) -> usize {
        self.get_seq_state(self.ke_kp.1).unwrap().1
    }

    // Unwrap message.
    // pub fn handle_msg(
    // &mut self,
    // msg: &TbinaryMessage<F, Link>,
    // info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    // ) -> Result<()> {
    // if self.appinst.is_some() {
    // ensure!(
    // self.appinst.as_ref().unwrap().base() == msg.link().base(),
    // "Bad message application instance."
    // );
    // }
    //
    // let preparsed = msg.parse_header()?;
    //
    // if preparsed.check_content_type(announce::TYPE) {
    // self.handle_announcement(preparsed, info)?;
    // Ok(())
    // } else if preparsed.check_content_type(change_key::TYPE) {
    // self.handle_change_key(preparsed, info)?;
    // Ok(())
    // } else if preparsed.check_content_type(signed_packet::TYPE) {
    // self.handle_signed_packet(preparsed, info)?;
    // Ok(())
    // } else if preparsed.check_content_type(tagged_packet::TYPE) {
    // self.handle_tagged_packet(preparsed, info)?;
    // Ok(())
    // } else
    //
    // if preparsed.check_content_type(keyload::TYPE) {
    // self.handle_keyload(preparsed, info)?;
    // Ok(())
    // } else
    // /
    // {
    // bail!("Unsupported content type: '{}'.", preparsed.content_type())
    // }
    // }
}
