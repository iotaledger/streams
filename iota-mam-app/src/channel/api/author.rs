use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::AsRef;
use std::str::FromStr;
use failure::{bail, ensure};

use iota_mam_core::{signature::mss, key_encapsulation::ntru, prng, psk, spongos, trits::{Trits}};

use iota_mam_protobuf3::{command::*, io, types::*};

use crate::Result;
use crate::channel::{api::*, msg::*};
use crate::core::{*, msg::{*, header::Header}};

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
pub struct AuthorT<Link, Store, LinkGen> {

    /// PRNG object used for MSS, NTRU, Spongos key generation, etc.
    prng: prng::PRNG,

    /// A default height of Merkle tree for new MSS private keys.
    /// It can be modified before changing keys.
    pub default_mss_height: usize,

    /// Own MSS private key.
    mss_sk: mss::PrivateKey,

    /// Own optional NTRU key pair.
    opt_ntru: Option<(ntru::PrivateKey, ntru::PublicKey)>,

    /// Subscribers' pre-shared keys.
    pub psks: Psks,

    /// Subscribers' trusted NTRU public keys.
    pub ntru_pks: NtruPks,

    /// Link store.
    store: RefCell<Store>,

    /// Link generator.
    link_gen: LinkGen,

    /// Link to the announce message, ie. application instance.
    appinst: Link,
}

impl<Link, Store, LinkGen> AuthorT<Link, Store, LinkGen> where
    Link: HasLink + AbsorbExternalFallback + Default + Clone + Eq,
    <Link as HasLink>::Base: Eq + ToString,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
    LinkGen: ChannelLinkGenerator<Link>,
{
    /// Create a new Author and generate MSS and optionally NTRU key pair.
    pub fn gen(store: Store, mut link_gen: LinkGen, prng: prng::PRNG, nonce: &Trits, mss_height: usize, with_ntru: bool) -> Self {
        let mss_nonce = nonce.clone();
        let mss_sk = mss::PrivateKey::gen(&prng, mss_nonce.slice(), mss_height);

        let appinst = link_gen.link_from(mss_sk.public_key());

        let opt_ntru = if with_ntru {
            let ntru_nonce = Trits::from_str("NTRUNONCE").unwrap();
            let key_pair = ntru::gen(&prng, ntru_nonce.slice());
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
            ntru_pks: HashMap::new(),

            store: RefCell::new(store),
            link_gen: link_gen,
            appinst: appinst,
        }
    }

    /// Create Header for the first (Announce) message in the channel.
    fn first_header(&mut self, content_type: &str) -> Header<Link> {
        let first_link = self.link_gen.link_from(self.mss_sk.public_key());
        Header::new(first_link, content_type)
    }

    /// Create Header for the message linked to `link_to`.
    fn next_header(&mut self, link_to: &<Link as HasLink>::Rel, content_type: &str) -> Header<Link> {
        let next_link = self.link_gen.link_from(link_to);
        Header::new(next_link, content_type)
    }

    /// Prepare Announcement message.
    pub fn prepare_announcement<'a>(&'a mut self) -> Result<PreparedMessage<'a, Link, Store, announce::ContentWrap>> {
        let header = self.first_header(announce::TYPE);
        let content = announce::ContentWrap {
            mss_sk: &self.mss_sk,
            ntru_pk: self.opt_ntru.as_ref().map(|key_pair| &key_pair.1),
        };
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Create Announce message.
    pub fn announce<'a>(&'a mut self, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        let wrapped = self
            .prepare_announcement()?
            .wrap()?;
        wrapped
            .commit(self.store.borrow_mut(), info)
    }

    /// Prepare ChangeKey message: generate new MSS key pair.
    pub fn prepare_change_key<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel) -> Result<PreparedMessage<'a, Link, Store, change_key::ContentWrap<'a, Link>>> {
        let mss_nonce = self.mss_sk.nonce().clone();
        let mss_sk = mss::PrivateKey::gen(&self.prng, mss_nonce.slice(), self.default_mss_height);

        let header = self.next_header(link_to, change_key::TYPE);

        let content = change_key::ContentWrap::new(link_to, mss_sk, &self.mss_sk);
        Ok(PreparedMessage::new(self.store.borrow(), header, content))
    }

    /// Generate a new MSS key pair, create change key message linked to the `link_to`
    /// and replace the current MSS key pair with the newly generated one.
    pub fn change_key(&mut self, link_to: &<Link as HasLink>::Rel, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
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
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        psks: Psks,
        ntru_pks: NtruPks)
        -> Result<PreparedMessage<'a, Link, Store, keyload::ContentWrap<'a, Link, Psks, NtruPks>>> where
        Psks: Clone + ExactSizeIterator<Item = (&'a psk::PskId, &'a psk::Psk)>,
        NtruPks: Clone + ExactSizeIterator<Item = (&'a ntru::Pkid, &'a ntru::PublicKey)>,
    {
        let header = self.next_header(link_to, keyload::TYPE);

        //TODO: trait MessageWrap { fn wrap(header, content) -> TrinaryMessage<Link> }
        //TODO: const NONCE_SIZE
        //TODO: get new unique nonce!
        let nonce = NTrytes::zero(3 * 27);
        //TODO: generate new unique key!
        //TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter
        let key = NTrytes::zero(spongos::KEY_SIZE);
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

    /*
    pub fn prepare_keyload<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel, psk_ids: &PskIds, ntru_pkids: &NtruPkids) -> Result<PreparedMessage<'a, Link, Store, keyload::ContentWrap<'a, Link, IPsks<'a>, INtruPks<'a>>>> {
        let psks = filter_psks(&self.psks, psk_ids);
        let ipsks = psks.iter().cloned();
        let ntru_pks = filter_ntru_pks(&self.ntru_pks, ntru_pkids);
        let intru_pks = ntru_pks.iter().cloned();
        self.do_prepare_keyload(link_to, ipsks, intru_pks)
    }

    pub fn prepare_keyload_for_everyone<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel) -> Result<PreparedMessage<'a, Link, Store, keyload::ContentWrap<'a, Link, Psks, NtruPks>>> {
        let ipsks = self.psks.iter();
        let intru_pks = self.ntru_pks.iter();
        self.do_prepare_keyload(link_to, ipsks, intru_pks)
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(&mut self, link_to: &<Link as HasLink>::Rel, psk_ids: &PskIds, ntru_pkids: &NtruPkids, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        self
            .prepare_keyload(link_to, psk_ids, ntru_pkids)?
            .wrap()?
            .commit(self.store.borrow_mut(), info)
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub fn share_keyload_for_everyone(&mut self, link_to: &<Link as HasLink>::Rel, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        self
            .prepare_keyload_for_everyone(link_to)?
            .wrap()?
            .commit(self.store.borrow_mut(), info)
    }
     */

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel, public_payload: &'a Trytes, masked_payload: &'a Trytes) -> Result<PreparedMessage<'a, Link, Store, signed_packet::ContentWrap<'a, Link>>> {
        let header = self.next_header(link_to, signed_packet::TYPE);
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
    pub fn sign_packet(&mut self, link_to: &<Link as HasLink>::Rel, public_payload: &Trytes, masked_payload: &Trytes, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        let wrapped = self
            .prepare_signed_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped
            .commit(self.store.borrow_mut(), info)
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel, public_payload: &'a Trytes, masked_payload: &'a Trytes) -> Result<PreparedMessage<'a, Link, Store, tagged_packet::ContentWrap<'a, Link>>> {
        let header = self.next_header(link_to, tagged_packet::TYPE);
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
    pub fn tag_packet(&mut self, link_to: &<Link as HasLink>::Rel, public_payload: &Trytes, masked_payload: &Trytes, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        let wrapped = self
            .prepare_tagged_packet(link_to, public_payload, masked_payload)?
            .wrap()?;
        wrapped
            .commit(self.store.borrow_mut(), info)
    }


    pub fn unwrap_tagged_packet<'a>(&self, preparsed: PreparsedMessage<'a, Link>) -> Result<UnwrappedMessage<Link, tagged_packet::ContentUnwrap<Link>>> {
        let mut content = tagged_packet::ContentUnwrap::new();
        preparsed.unwrap(&*self.store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_tagged_packet<'a>(&mut self, preparsed: PreparsedMessage<'a, Link>, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<(Trytes, Trytes)> {
        let content = self
            .unwrap_tagged_packet(preparsed)?
            .commit(self.store.borrow_mut(), info)?;
        Ok((content.public_payload, content.masked_payload))
    }

    /// Unwrap message.
    pub fn handle_msg(&mut self, msg: &TrinaryMessage<Link>, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<()> {
        let preparsed = msg.parse_header()?;

        if preparsed.check_content_type(tagged_packet::TYPE) {
            self.handle_tagged_packet(preparsed, info)?;
            Ok(())
        } else
        {
            bail!("Unsupported content type: '{}'.", preparsed.content_type())
        }
    }
}
