use anyhow::{
    bail,
    ensure,
    Result,
};
use std::{
    cell::RefCell,
    collections::{
        HashMap,
        HashSet,
    },
    fmt::Debug,
    str::FromStr,
};

use iota_streams_core::{
    prng,
    psk,
    sponge::spongos,
};
use iota_streams_core_edsig::{signature::ed25519, key_exchange::x25519};

use iota_streams_app::message::{
    header::Header,
    *,
};
use iota_streams_protobuf3::types::*;

use super::*;
use crate::message::*;

/// Generic Channel Author type parametrised by the type of links, link store and
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
pub struct AuthorT<F, Link, Store, LinkGen>
{
    /// PRNG object used for Ed25519, X25519, Spongos key generation, etc.
    prng: prng::Prng<F>,

    /// Own Ed25519 private key.
    pub(crate) sig_sk: ed25519::SecretKey,

    /// Own optional x25519 key pair.
    pub(crate) opt_ke: Option<(x25519::StaticSecret, x25519::PublicKey)>,

    /// Subscribers' pre-shared keys.
    pub psks: psk::Psks,

    ///// Subscribers' trusted X25519 public keys.
    //pub ke_pks: x25519::Pks,

    /// Link store.
    store: RefCell<Store>,

    /// Link generator.
    pub(crate) link_gen: LinkGen,

    /// Link to the announce message, ie. application instance.
    pub(crate) appinst: Link,
}

impl<F, Link, Store, LinkGen> AuthorT<F, Link, Store, LinkGen>
where
    F: PRP + Clone + Default,
    Link: HasLink + AbsorbExternalFallback<F> + Default + Clone + Eq,
    <Link as HasLink>::Base: Eq + Debug,
    <Link as HasLink>::Rel: Eq + Debug + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LinkGen: ChannelLinkGenerator<Link>,
{
    /// Create a new Author and generate MSS and optionally NTRU key pair.
    pub fn gen(
        store: Store,
        mut link_gen: LinkGen,
        prng: prng::Prng<F>,
        nonce: &[u8],
        mss_height: usize,
        with_ntru: bool,
    ) -> Self {
        /*
        let mss_nonce = nonce.clone();
        let sig_sk = ed25519::PrivateKey::gen(&prng, mss_nonce.slice(), mss_height);

        let appinst = link_gen.link_from(sig_sk.public_key());

        let opt_ntru = if with_ntru {
            let ntru_nonce = Tbits::::from_str("NTRUNONCE").unwrap();
            let key_pair = x25519::gen_keypair(&prng, ntru_nonce.slice());
            Some(key_pair)
        } else {
            None
        };

        Self {
            prng: prng,
            default_mss_height: mss_height,
            sig_sk: sig_sk,
            opt_ntru: opt_ntru,

            psks: HashMap::new(),
            ke_pks: HashSet::new(),

            store: RefCell::new(store),
            link_gen: link_gen,
            appinst: appinst,
        }
         */
        panic!("not implemented");
    }

    /// Prepare Announcement message.
    pub fn prepare_announcement<'a>(
        &'a mut self,
    ) -> Result<PreparedMessage<'a, F, Link, Store, announce::ContentWrap<F>>> {
        panic!("not implemented");
        /*
        // Create Header for the first message in the channel.
        let header = self.link_gen.header_from(self.sig_sk.public_key(), announce::TYPE);
        let content = announce::ContentWrap {
            sig_sk: &self.sig_sk,
            ke_pk: self.opt_ke.as_ref().map(|key_pair| &key_pair.1),
            _phantom: std::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
         */
    }

    /// Create Announce message.
    pub fn announce<'a>(
        &'a mut self,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_announcement()?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /*
    fn do_prepare_keyload<'a, Psks, NtruPks>(
        &'a self,
        header: Header<Link>,
        link_to: &'a <Link as HasLink>::Rel,
        psks: Psks,
        ke_pks: NtruPks,
    ) -> Result<PreparedMessage<'a, F, Link, Store, keyload::ContentWrap<'a, F, P::PrngG, Link, Psks, NtruPks>>>
    where
        Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
        NtruPks: Clone + ExactSizeIterator<Item = ntru::INtruPk<'a, F>>,
    {
        let nonce = NBytes(prng::random_nonce(spongos::Spongos::<F>::NONCE_SIZE));
        let key = NBytes(prng::random_key(spongos::Spongos::<F>::KEY_SIZE));
        let content = keyload::ContentWrap {
            link: link_to,
            nonce: nonce,
            key: key,
            psks: psks,
            prng: &self.prng,
            ke_pks: ke_pks,
            _phantom: std::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    pub fn prepare_keyload<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        psk_ids: &psk::PskIds,
        ntru_pkids: &ntru::NtruPkids,
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
                std::vec::IntoIter<psk::IPsk<'a>>,
                std::vec::IntoIter<ntru::INtruPk<'a, F>>,
            >,
        >,
    > {
        let header = self.link_gen.header_from(link_to, keyload::TYPE);
        let psks = psk::filter_psks(&self.psks, psk_ids);
        let ke_pks = ntru::filter_ke_pks(&self.ke_pks, ntru_pkids);
        self.do_prepare_keyload(header, link_to, psks.into_iter(), ke_pks.into_iter())
    }

    pub fn prepare_keyload_for_everyone<'a>(
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
                P::PrngG,
                Link,
                std::collections::hash_map::Iter<psk::PskId, psk::Psk>,
                std::collections::hash_set::Iter<ntru::PublicKey<F>>,
            >,
        >,
    > {
        let header = self.link_gen.header_from(link_to, keyload::TYPE);
        let ipsks = self.psks.iter();
        let ike_pks = self.ke_pks.iter();
        self.do_prepare_keyload(header, link_to, ipsks, ike_pks)
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        psk_ids: &psk::PskIds,
        ntru_pkids: &ntru::NtruPkids,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_keyload(link_to, psk_ids, ntru_pkids)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub fn share_keyload_for_everyone(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self.prepare_keyload_for_everyone(link_to)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }
     */

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<'a, F, Link, Store, signed_packet::ContentWrap<'a, F, Link>>> {
        let header = self.link_gen.header_from(link_to, signed_packet::TYPE);
        let content = signed_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            sig_sk: &self.sig_sk,
            _phantom: std::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Create a signed message with public and masked payload.
    pub fn sign_packet(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        public_payload: &Bytes,
        masked_payload: &Bytes,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<TbinaryMessage<F, Link>> {
        let wrapped = self
            .prepare_signed_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<'a, F, Link, Store, tagged_packet::ContentWrap<'a, F, Link>>> {
        let header = self.link_gen.header_from(link_to, tagged_packet::TYPE);
        let content = tagged_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            _phantom: std::marker::PhantomData,
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

    fn ensure_appinst<'a>(&self, preparsed: &PreparsedMessage<'a, F, Link>) -> Result<()> {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        Ok(())
    }

    /*
    fn lookup_psk<'b>(&'b self, pskid: &psk::PskId) -> Option<&'b psk::Psk> {
        self.psks.get(pskid)
    }

    fn lookup_ke_sk<'b>(&'b self, ke_pkid: &ntru::Pkid) -> Option<&'b ntru::PrivateKey<F>> {
        self.opt_ntru.as_ref().map_or(None, |(own_ntru_sk, own_ntru_pk)| {
            if own_ntru_pk.cmp_pkid(ntru_pkid) {
                Some(own_ntru_sk)
            } else {
                None
            }
        })
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
                for<'c> fn(&'c Self, &ntru::Pkid) -> Option<&'c ntru::PrivateKey<F>>,
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
            for<'c> fn(&'c Self, &ntru::Pkid) -> Option<&'c ntru::PrivateKey<F>>,
        >::new(self, Self::lookup_psk, Self::lookup_ke_sk);
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or NTRU private key (if any).
    pub fn handle_keyload<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let _content = self.unwrap_keyload(preparsed)?.commit(self.store.borrow_mut(), info)?;
        // Unwrapped nonce and key in content are not used explicitly.
        // The resulting spongos state is joined into a protected message state.
        Ok(())
    }
     */

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

    /*
    pub fn unwrap_subscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, subscribe::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        if let Some((own_ke_sk, _)) = &self.opt_ke {
            let content = subscribe::ContentUnwrap::new(own_ke_sk);
            preparsed.unwrap(&*self.store.borrow(), content)
        } else {
            bail!("Author doesn't have X25519 key pair.")
        }
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_subscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let content = self
            .unwrap_subscribe(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        //TODO: trust content.subscriber_ntru_pk and add to the list of subscribers only if trusted.
        let subscriber_ntru_pk = content.subscriber_ntru_pk;
        self.ke_pks.insert(subscriber_ntru_pk);
        // Unwrapped unsubscribe_key is not used explicitly.
        Ok(())
    }

    pub fn unwrap_unsubscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, unsubscribe::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = unsubscribe::ContentUnwrap::new();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_unsubscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let _content = self
            .unwrap_unsubscribe(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok(())
    }
     */

    /// Unwrap message with default logic.
    pub fn handle_msg(
        &mut self,
        msg: &TbinaryMessage<F, Link>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let preparsed = msg.parse_header()?;
        self.ensure_appinst(&preparsed)?;

        if preparsed.check_content_type(tagged_packet::TYPE) {
            self.handle_tagged_packet(preparsed, info)?;
            Ok(())
        } else if preparsed.check_content_type(announce::TYPE) {
            bail!("Can't handle announce message.")
        } else if preparsed.check_content_type(signed_packet::TYPE) {
            bail!("Can't handle signed_packet message.")
        } else {
            bail!("Unsupported content type: '{}'.", preparsed.content_type())
        }
    }
}
