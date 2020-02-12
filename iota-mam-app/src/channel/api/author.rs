use std::collections::HashMap;
use std::convert::AsRef;
use std::str::FromStr;
use failure::{bail, ensure};

use iota_mam_core::{signature::mss, key_encapsulation::ntru, prng, psk, spongos, trits::{Trits}};

use iota_mam_protobuf3 as protobuf3;
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};

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
    store: Store,

    /// Link generator.
    link_gen: LinkGen,

    /// Link to the announce message, ie. application instance.
    appinst: Link,
}

/// Message associated info, just message type indicator.
#[derive(Copy, Clone)]
pub enum MsgInfo {
    Announce,
    ChangeKey,
    Keyload,
    Subscribe,
    Unsubscribe,
    SignedPacket,
    TaggedPacket,
}

/// Customize Author.
use crate::core::transport::tangle::*;

/// * Select Link type.
pub type Address = TangleAddress;

/// * Select Link Generator.
pub type LinkGen = DefaultTangleLinkGenerator;

/// * Select Link Store.
pub type Store = DefaultLinkStore<Address, MsgInfo>;

/// * Define Author type.
pub type Author = AuthorT<Address, Store, LinkGen>;

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

            store: store,
            link_gen: link_gen,
            appinst: appinst,
        }
    }

    fn first_header(&mut self, content_type: &str) -> Header<Link> {
        let first_link = self.link_gen.link_from(self.mss_sk.public_key());
        Header::new(first_link, content_type)
    }

    fn next_header(&mut self, link_to: &<Link as HasLink>::Rel, content_type: &str) -> Header<Link> {
        let next_link = self.link_gen.link_from(link_to);
        Header::new(next_link, content_type)
    }

    pub fn prepare_announcement<'a>(&'a mut self) -> Result<PreparedMessage<'a, Link, Store, announce::ContentWrap>> {
        let header = self.first_header(announce::TYPE);
        let content = announce::ContentWrap {
            mss_sk: &self.mss_sk,
            ntru_pk: self.opt_ntru.as_ref().map(|key_pair| &key_pair.1),
        };
        Ok(PreparedMessage::new(&mut self.store, header, content))
    }

    /// Create Announce message.
    pub fn announce<'a>(&'a mut self, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        self.prepare_announcement()?.commit(info)
    }

    /*
    pub fn prepare_change_key<'a>(&'a mut self, link_to: &'a <Link as HasLink>::Rel) -> Result<PreparedMessage<'a, Link, Store, change_key::ContentWrap<'a, <Link as HasLink>::Rel, Store>>> {
        let mss_nonce = self.mss_sk.nonce().clone();
        let mss_sk = mss::PrivateKey::gen(&self.prng, mss_nonce.slice(), self.default_mss_height);

        let header = self.next_header(link_to, change_key::TYPE);

        let content = change_key::ContentWrap {
            store: &self.store,
            link: link_to,
            mss_pk: mss_sk.public_key(),
            mss_sk: &mss_sk,
            mss_linked_sk: &self.mss_sk,
        };
        Ok(PreparedMessage::new(&mut self.store, header, content))
    }
     */

    /// Generate a new MSS key pair, create change key message linked to the `link_to`
    /// and replace the current MSS key pair with the newly generated one.
    pub fn change_key(&mut self, link_to: &<Link as HasLink>::Rel) -> Result<TrinaryMessage<Link>> {
        let mss_nonce = self.mss_sk.nonce().clone();
        let mss_sk = mss::PrivateKey::gen(&self.prng, mss_nonce.slice(), self.default_mss_height);

        let header = self.next_header(link_to, change_key::TYPE);

        let content = change_key::ContentWrap {
            store: &self.store,
            link: link_to,
            mss_pk: mss_sk.public_key(),
            mss_sk: &mss_sk,
            mss_linked_sk: &self.mss_sk,
        };

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            header.sizeof(&mut ctx)?;
            content.sizeof(&mut ctx)?;
            ctx.get_size()
        };
        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            header.wrap(&mut ctx)?;
            content.wrap(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");
        }

        // Update MSS private key, drop the old one.
        //TODO: Return the old MSS key or add a container of MSS private keys?
        self.mss_sk = mss_sk;

        Ok(TrinaryMessage{ link: header.link, body: buf, })
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(&mut self, link_to: &<Link as HasLink>::Rel, psk_ids: &PskIds, ntru_pkids: &NtruPkids) -> Result<TrinaryMessage<Link>> {
        let header = self.next_header(link_to, keyload::TYPE);

        let psks = filter_psks(&self.psks, psk_ids);
        let ipsks = psks.iter().cloned();
        let ntru_pks = filter_ntru_pks(&self.ntru_pks, ntru_pkids);
        let intru_pks = ntru_pks.iter().cloned();

        //TODO: trait MessageWrap { fn wrap(header, content) -> TrinaryMessage<Link> }
        //TODO: const NONCE_SIZE
        //TODO: get new unique nonce!
        let nonce = NTrytes::zero(3 * 27);
        //TODO: generate new unique key!
        //TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter
        let key = NTrytes::zero(spongos::KEY_SIZE);
        let content = keyload::ContentWrap {
            store: &self.store,
            link: link_to,
            nonce: nonce,
            key: key,
            psks: ipsks,
            prng: &self.prng,
            ntru_pks: intru_pks,
        };

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            header.sizeof(&mut ctx)?;
            content.sizeof(&mut ctx)?;
            ctx.get_size()
        };
        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            header.wrap(&mut ctx)?;
            content.wrap(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");
        }

        Ok(TrinaryMessage{ link: header.link, body: buf, })
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub fn share_keyload_with_all_subscribers(&mut self, link_to: &<Link as HasLink>::Rel) -> Result<TrinaryMessage<Link>> {
        let header = self.next_header(link_to, keyload::TYPE);

        let ipsks = self.psks.iter();
        let intru_pks = self.ntru_pks.iter();

        //TODO: trait MessageWrap { fn wrap(header, content) -> TrinaryMessage<Link> }
        //TODO: const NONCE_SIZE
        //TODO: get new unique nonce!
        let nonce = NTrytes::zero(3 * 27);
        //TODO: generate new unique key!
        //TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter
        let key = NTrytes::zero(spongos::KEY_SIZE);
        let content = keyload::ContentWrap {
            store: &self.store,
            link: link_to,
            nonce: nonce,
            key: key,
            psks: ipsks,
            prng: &self.prng,
            ntru_pks: intru_pks,
        };

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            header.sizeof(&mut ctx)?;
            content.sizeof(&mut ctx)?;
            ctx.get_size()
        };
        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            header.wrap(&mut ctx)?;
            content.wrap(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");
        }

        Ok(TrinaryMessage{ link: header.link, body: buf, })
    }

    /// Create a signed message with public and masked payload.
    pub fn sign_packet(&mut self, link_to: &<Link as HasLink>::Rel, public_payload: &Trytes, masked_payload: &Trytes) -> Result<TrinaryMessage<Link>> {
        //TODO: Reserve a few WOTS keys for change key?
        let header = self.next_header(link_to, signed_packet::TYPE);
        let content = signed_packet::ContentWrap {
            store: &self.store,
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            mss_sk: &self.mss_sk,
        };

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            header.sizeof(&mut ctx)?;
            content.sizeof(&mut ctx)?;
            ctx.get_size()
        };
        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            header.wrap(&mut ctx)?;
            content.wrap(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");
        }

        Ok(TrinaryMessage{ link: header.link, body: buf, })
    }
    
    /// Create a tagged (ie. MACed) message with public and masked payload.
    /// Tagged messages must be linked to a secret spongos state, ie. keyload or a message linked to keyload.
    pub fn tag_packet(&mut self, link_to: &<Link as HasLink>::Rel, public_payload: &Trytes, masked_payload: &Trytes) -> Result<TrinaryMessage<Link>> {
        let header = self.next_header(link_to, tagged_packet::TYPE);
        let content = tagged_packet::ContentWrap {
            store: &self.store,
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
        };

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            header.sizeof(&mut ctx)?;
            content.sizeof(&mut ctx)?;
            ctx.get_size()
        };
        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            header.wrap(&mut ctx)?;
            content.wrap(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");
        }

        Ok(TrinaryMessage{ link: header.link, body: buf, })
    }
    
    fn handle_tagged_packet<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<(Trytes, Trytes)> {
        let mut content = tagged_packet::ContentUnwrap::new(&self.store);
        content.unwrap(ctx)?;
        Ok((content.public_payload, content.masked_payload))
    }

    /// Unwrap message.
    pub fn handle_msg(&mut self, msg: &TrinaryMessage<Link>) -> Result<()> {
        ensure!(self.appinst.base() == msg.link().base(),
                "Application instance is {}, but message is addressed to {}.",
                self.appinst.base().to_string(), msg.link.base().to_string());

        let mut ctx = unwrap::Context::new(msg.body.slice());
        let mut hdr = Header::<Link>::default();
        hdr.unwrap(&mut ctx)?;

        if (hdr.content_type.0).eq_str(tagged_packet::TYPE) {
            self.handle_tagged_packet(&mut ctx)?;
            Ok(())
        } else {
            bail!("Unsupported content type: '{}'.", (hdr.content_type.0).to_string())
        }
    }
}
