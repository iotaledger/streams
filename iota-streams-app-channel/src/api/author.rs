use failure::{bail, ensure, Fallible};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::str::FromStr;

use iota_streams_core::{
    prng, psk,
    sponge::spongos,
    tbits::{
        trinary,
        word::{IntTbitWord, SpongosTbitWord, StringTbitWord},
        Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

use iota_streams_app::message::{header::Header, *};
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
pub struct AuthorT<TW, F, P, Link, Store, LinkGen>
where
    P: mss::Parameters<TW>,
{
    /// PRNG object used for MSS, NTRU, Spongos key generation, etc.
    prng: prng::Prng<TW, P::PrngG>,

    /// A default height of Merkle tree for new MSS private keys.
    /// It can be modified before changing keys.
    pub default_mss_height: usize,

    /// Own MSS private key.
    mss_sk: mss::PrivateKey<TW, P>,

    /// Own optional NTRU key pair.
    opt_ntru: Option<(ntru::PrivateKey<TW, F>, ntru::PublicKey<TW, F>)>,

    /// Subscribers' pre-shared keys.
    pub psks: psk::Psks<TW>,

    /// Subscribers' trusted NTRU public keys.
    pub ntru_pks: ntru::NtruPks<TW, F>,

    /// Link store.
    store: RefCell<Store>,

    /// Link generator.
    link_gen: LinkGen,

    /// Link to the announce message, ie. application instance.
    appinst: Link,
}

impl<TW, F, P, Link, Store, LinkGen> AuthorT<TW, F, P, Link, Store, LinkGen>
where
    TW: IntTbitWord + StringTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Clone + Default,
    //G: PRP<TW> + Clone + Default,
    P: mss::Parameters<TW>,
    Link: HasLink + AbsorbExternalFallback<TW, F> + Default + Clone + Eq,
    <Link as HasLink>::Base: Eq + Debug,
    <Link as HasLink>::Rel: Eq + Debug + Default + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
    LinkGen: ChannelLinkGenerator<TW, P, Link>,
{
    /// Create a new Author and generate MSS and optionally NTRU key pair.
    pub fn gen(
        store: Store,
        mut link_gen: LinkGen,
        prng: prng::Prng<TW, P::PrngG>,
        nonce: &Tbits<TW>,
        mss_height: usize,
        with_ntru: bool,
    ) -> Self {
        let mss_nonce = nonce.clone();
        let mss_sk = mss::PrivateKey::<TW, P>::gen(&prng, mss_nonce.slice(), mss_height);

        let appinst = link_gen.link_from(mss_sk.public_key());

        let opt_ntru = if with_ntru {
            let ntru_nonce = Tbits::<TW>::from_str("NTRUNONCE").unwrap();
            let key_pair = ntru::gen_keypair::<TW, F, P::PrngG>(&prng, ntru_nonce.slice());
            Some(key_pair)
        } else {
            None
        };

        Self {
            prng: prng,
            default_mss_height: mss_height,
            mss_sk: mss_sk,
            opt_ntru: opt_ntru,

            psks: HashMap::new(),
            ntru_pks: HashSet::new(),

            store: RefCell::new(store),
            link_gen: link_gen,
            appinst: appinst,
        }
    }

    /// Prepare Announcement message.
    pub fn prepare_announcement<'a>(
        &'a mut self,
    ) -> Fallible<PreparedMessage<'a, TW, F, Link, Store, announce::ContentWrap<TW, F, P>>> {
        // Create Header for the first message in the channel.
        let header = self
            .link_gen
            .header_from(self.mss_sk.public_key(), announce::TYPE);
        let content = announce::ContentWrap {
            mss_sk: &self.mss_sk,
            ntru_pk: self.opt_ntru.as_ref().map(|key_pair| &key_pair.1),
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Create Announce message.
    pub fn announce<'a>(
        &'a mut self,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let wrapped = self.prepare_announcement()?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare ChangeKey message: generate new MSS key pair.
    pub fn prepare_change_key<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Fallible<PreparedMessage<'a, TW, F, Link, Store, change_key::ContentWrap<'a, TW, P, Link>>>
    {
        let mss_nonce = self.mss_sk.nonce().clone();
        let mss_sk = mss::PrivateKey::gen(&self.prng, mss_nonce.slice(), self.default_mss_height);

        let header = self.link_gen.header_from(link_to, change_key::TYPE);

        let content = change_key::ContentWrap::new(link_to, mss_sk, &self.mss_sk);
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Generate a new MSS key pair, create change key message linked to the `link_to`
    /// and replace the current MSS key pair with the newly generated one.
    pub fn change_key(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let (wrapped, mss_sk) = {
            let prepared = self.prepare_change_key(link_to)?;
            let wrapped = prepared.wrap()?;

            // Update MSS private key, drop the old one.
            //TODO: Return the old MSS key or add a container of MSS private keys?
            (wrapped, prepared.content.mss_sk)
        };
        self.mss_sk = mss_sk;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    fn do_prepare_keyload<'a, Psks, NtruPks>(
        &'a self,
        header: Header<TW, Link>,
        link_to: &'a <Link as HasLink>::Rel,
        psks: Psks,
        ntru_pks: NtruPks,
    ) -> Fallible<
        PreparedMessage<
            'a,
            TW,
            F,
            Link,
            Store,
            keyload::ContentWrap<'a, TW, F, P::PrngG, Link, Psks, NtruPks>,
        >,
    >
    where
        Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a, TW>>,
        NtruPks: Clone + ExactSizeIterator<Item = ntru::INtruPk<'a, TW, F>>,
    {
        //TODO: trait MessageWrap { fn wrap(header, content) -> TbinaryMessage<TW, F, Link> }
        //TODO: const NONCE_SIZE
        //TODO: get new unique nonce!
        let nonce = NTrytes::zero(spongos::Spongos::<TW, F>::KEY_SIZE);
        //TODO: generate new unique key!
        //TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter
        let key = NTrytes::zero(spongos::Spongos::<TW, F>::KEY_SIZE);
        let content = keyload::ContentWrap {
            link: link_to,
            nonce: nonce,
            key: key,
            psks: psks,
            prng: &self.prng,
            ntru_pks: ntru_pks,
            _phantom: std::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    pub fn prepare_keyload<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        psk_ids: &psk::PskIds<TW>,
        ntru_pkids: &ntru::NtruPkids<TW>,
    ) -> Fallible<
        PreparedMessage<
            'a,
            TW,
            F,
            Link,
            Store,
            keyload::ContentWrap<
                'a,
                TW,
                F,
                P::PrngG,
                Link,
                std::vec::IntoIter<psk::IPsk<'a, TW>>,
                std::vec::IntoIter<ntru::INtruPk<'a, TW, F>>,
            >,
        >,
    > {
        let header = self.link_gen.header_from(link_to, keyload::TYPE);
        let psks = psk::filter_psks(&self.psks, psk_ids);
        let ntru_pks = ntru::filter_ntru_pks(&self.ntru_pks, ntru_pkids);
        self.do_prepare_keyload(header, link_to, psks.into_iter(), ntru_pks.into_iter())
    }

    pub fn prepare_keyload_for_everyone<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Fallible<
        PreparedMessage<
            'a,
            TW,
            F,
            Link,
            Store,
            keyload::ContentWrap<
                'a,
                TW,
                F,
                P::PrngG,
                Link,
                std::collections::hash_map::Iter<psk::PskId<TW>, psk::Psk<TW>>,
                std::collections::hash_set::Iter<ntru::PublicKey<TW, F>>,
            >,
        >,
    > {
        let header = self.link_gen.header_from(link_to, keyload::TYPE);
        let ipsks = self.psks.iter();
        let intru_pks = self.ntru_pks.iter();
        self.do_prepare_keyload(header, link_to, ipsks, intru_pks)
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        psk_ids: &psk::PskIds<TW>,
        ntru_pkids: &ntru::NtruPkids<TW>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let wrapped = self.prepare_keyload(link_to, psk_ids, ntru_pkids)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub fn share_keyload_for_everyone(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let wrapped = self.prepare_keyload_for_everyone(link_to)?.wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Trytes<TW>,
        masked_payload: &'a Trytes<TW>,
    ) -> Fallible<
        PreparedMessage<'a, TW, F, Link, Store, signed_packet::ContentWrap<'a, TW, F, P, Link>>,
    > {
        let header = self.link_gen.header_from(link_to, signed_packet::TYPE);
        let content = signed_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            mss_sk: &self.mss_sk,
            _phantom: std::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Create a signed message with public and masked payload.
    pub fn sign_packet(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        public_payload: &Trytes<TW>,
        masked_payload: &Trytes<TW>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let wrapped = self
            .prepare_signed_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Trytes<TW>,
        masked_payload: &'a Trytes<TW>,
    ) -> Fallible<
        PreparedMessage<'a, TW, F, Link, Store, tagged_packet::ContentWrap<'a, TW, F, Link>>,
    > {
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
        public_payload: &Trytes<TW>,
        masked_payload: &Trytes<TW>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TbinaryMessage<TW, F, Link>> {
        let wrapped = self
            .prepare_tagged_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped.commit(self.store.borrow_mut(), info)
    }

    fn lookup_psk<'b>(&'b self, pskid: &psk::PskId<TW>) -> Option<&'b psk::Psk<TW>> {
        self.psks.get(pskid)
    }

    fn lookup_ntru_sk<'b>(
        &'b self,
        ntru_pkid: &ntru::Pkid<TW>,
    ) -> Option<&'b ntru::PrivateKey<TW, F>> {
        self.opt_ntru
            .as_ref()
            .map_or(None, |(own_ntru_sk, own_ntru_pk)| {
                if own_ntru_pk.cmp_pkid(ntru_pkid) {
                    Some(own_ntru_sk)
                } else {
                    None
                }
            })
    }

    pub fn unwrap_keyload<'a, 'b>(
        &'b self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
    ) -> Fallible<
        UnwrappedMessage<
            TW,
            F,
            Link,
            keyload::ContentUnwrap<
                'b,
                TW,
                F,
                Link,
                Self,
                for<'c> fn(&'c Self, &psk::PskId<TW>) -> Option<&'c psk::Psk<TW>>,
                for<'c> fn(&'c Self, &ntru::Pkid<TW>) -> Option<&'c ntru::PrivateKey<TW, F>>,
            >,
        >,
    > {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        let content = keyload::ContentUnwrap::<
            'b,
            TW,
            F,
            Link,
            Self,
            for<'c> fn(&'c Self, &psk::PskId<TW>) -> Option<&'c psk::Psk<TW>>,
            for<'c> fn(&'c Self, &ntru::Pkid<TW>) -> Option<&'c ntru::PrivateKey<TW, F>>,
        >::new(self, Self::lookup_psk, Self::lookup_ntru_sk);
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or NTRU private key (if any).
    pub fn handle_keyload<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<()> {
        let _content = self
            .unwrap_keyload(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        // Unwrapped nonce and key in content are not used explicitly.
        // The resulting spongos state is joined into a protected message state.
        Ok(())
    }

    pub fn unwrap_tagged_packet<'a>(
        &self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
    ) -> Fallible<UnwrappedMessage<TW, F, Link, tagged_packet::ContentUnwrap<TW, F, Link>>> {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        let content = tagged_packet::ContentUnwrap::new();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_tagged_packet<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<(Trytes<TW>, Trytes<TW>)> {
        let content = self
            .unwrap_tagged_packet(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok((content.public_payload, content.masked_payload))
    }

    pub fn unwrap_subscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
    ) -> Fallible<UnwrappedMessage<TW, F, Link, subscribe::ContentUnwrap<TW, F, Link>>> {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        if let Some((own_ntru_sk, _)) = &self.opt_ntru {
            let content = subscribe::ContentUnwrap::new(own_ntru_sk);
            preparsed.unwrap(&*self.store.borrow(), content)
        } else {
            bail!("Author doesn't have NTRU key pair.")
        }
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_subscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<()> {
        let content = self
            .unwrap_subscribe(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        //TODO: trust content.subscriber_ntru_pk and add to the list of subscribers only if trusted.
        let subscriber_ntru_pk = content.subscriber_ntru_pk;
        self.ntru_pks.insert(subscriber_ntru_pk);
        // Unwrapped unsubscribe_key is not used explicitly.
        Ok(())
    }

    pub fn unwrap_unsubscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
    ) -> Fallible<UnwrappedMessage<TW, F, Link, unsubscribe::ContentUnwrap<TW, F, Link>>> {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        let content = unsubscribe::ContentUnwrap::new();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_unsubscribe<'a>(
        &mut self,
        preparsed: PreparsedMessage<'a, TW, F, Link>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<()> {
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );
        let _content = self
            .unwrap_unsubscribe(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok(())
    }

    /// Unwrap message with default logic.
    pub fn handle_msg(
        &mut self,
        msg: &TbinaryMessage<TW, F, Link>,
        info: <Store as LinkStore<TW, F, <Link as HasLink>::Rel>>::Info,
    ) -> Fallible<()> {
        let preparsed = msg.parse_header()?;
        ensure!(
            self.appinst.base() == preparsed.header.link.base(),
            "Message sent to another channel instance."
        );

        //TODO: Validate appinst.
        if preparsed.check_content_type(tagged_packet::TYPE) {
            self.handle_tagged_packet(preparsed, info)?;
            Ok(())
        } else if preparsed.check_content_type(announce::TYPE) {
            bail!("Can't handle announce message.")
        } else if preparsed.check_content_type(change_key::TYPE) {
            bail!("Can't handle change_key message.")
        } else if preparsed.check_content_type(signed_packet::TYPE) {
            bail!("Can't handle signed_packet message.")
        } else {
            bail!("Unsupported content type: '{}'.", preparsed.content_type())
        }
    }
}
