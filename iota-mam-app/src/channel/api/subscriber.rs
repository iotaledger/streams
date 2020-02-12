use std::collections::HashMap;
use std::convert::AsRef;
use std::str::FromStr;
use std::string::ToString;
use failure::{bail, ensure};

use iota_mam_core::{signature::mss, key_encapsulation::ntru, prng, psk, spongos, trits::{Trits}};

use iota_mam_protobuf3 as protobuf3;
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};

use crate::Result;
use crate::channel::{api::*, msg::*};
use crate::core::{*, msg::{*, header::Header}};

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
pub struct SubscriberT<Link, Store, LinkGen> {

    /// PRNG used for NTRU, Spongos key generation, etc.
    prng: prng::PRNG,

    /// Own optional pre-shared key.
    opt_psk: Option<(psk::PskId, psk::Psk)>,

    /// Own optional NTRU key pair.
    opt_ntru: Option<(ntru::PrivateKey, ntru::PublicKey)>,

    /// Address of the Announce message or nothing if Subscriber is not registered to
    /// the channel instance.
    appinst: Option<Link>,

    /// Author's MSS public key, or nothing if Subscriber is not registered to
    /// the channel instance.
    //TODO: Store also Author's old MSS public keys?
    author_mss_pk: Option<mss::PublicKey>,

    /// Author's NTRU public key or nothing if Author has no NTRU key pair.
    author_ntru_pk: Option<ntru::PublicKey>,

    /// Link store.
    store: Store,

    /// Link generator.
    link_gen: LinkGen,
}

pub enum MsgInfo {}

/// Customize Subscriber.
use crate::core::transport::tangle::*;

/// * Select Link type.
pub type Address = TangleAddress;

/// * Select Link Generator.
pub type LinkGen = DefaultTangleLinkGenerator;

/// * Select Link Store.
pub type Store = DefaultLinkStore<Address, MsgInfo>;

/// * Define Subscriber type.
pub type Subscriber = SubscriberT<Address, Store, LinkGen>;

impl<Link, Store, LinkGen> SubscriberT<Link, Store, LinkGen> where
    Link: HasLink + AbsorbExternalFallback + Default + Clone + Eq,
    <Link as HasLink>::Base: Eq,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
    LinkGen: ChannelLinkGenerator<Link>,
{
    /// Create a new Subscriber and optionally generate NTRU key pair.
    pub fn gen(store: Store, link_gen: LinkGen, prng: prng::PRNG, nonce: &Trits, mss_height: usize, with_ntru: bool) -> Self {
        let opt_ntru = if with_ntru {
            let ntru_nonce = Trits::from_str("NTRUNONCE").unwrap();
            let key_pair = ntru::gen(&prng, ntru_nonce.slice());
            Some(key_pair)
        } else {
            None
        };

        Self {
            prng: prng,
            opt_ntru: opt_ntru,
            opt_psk: None,

            appinst: None,
            author_mss_pk: None,
            author_ntru_pk: None,

            store: store,
            link_gen: link_gen,
        }
    }

    /// Bind Subscriber (or anonymously subscribe) to the channel announced
    /// in the message.
    fn handle_announce<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        let mut content = announce::ContentUnwrap::default();
        content.unwrap(ctx)?;
        //TODO: Verify trust to Author's MSS public key?
        self.author_mss_pk = Some(content.mss_pk);
        self.author_ntru_pk = content.ntru_pk;
        Ok(())
    }

    /// Verify new Author's MSS public key and update Author's MSS public key.
    fn handle_change_key<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ensure!(self.author_mss_pk.is_some(), "No Author's MSS public key found.");
        let mss_linked_pk = self.author_mss_pk.as_ref().unwrap();
        let mut content = change_key::ContentUnwrap::new(&self.store, mss_linked_pk);
        content.unwrap(ctx)?;
        self.author_mss_pk = Some(content.mss_pk);
        Ok(())
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or NTRU private key (if any).
    fn handle_keyload<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ensure!(self.opt_psk.is_some() || self.opt_ntru.is_some(),
                "No key information (PSK or NTRU) to unwrap keyload.");

        let mut content = keyload::ContentUnwrap::new(
            &self.store,
            |pskid_to_find| self
                .opt_psk
                .as_ref()
                .map_or(None, |(own_pskid, own_psk)|
                        if pskid_to_find == own_pskid
                        { Some(&own_psk) } else { None }
                ),
            |ntru_pkid_to_find| self
                .opt_ntru
                .as_ref()
                .map_or(None, |(own_ntru_sk, own_ntru_pk)|
                        if ntru_pkid_to_find.slice() == own_ntru_pk.id()
                        { Some(&own_ntru_sk) } else { None }
                ),
        );
        content.unwrap(ctx)?;
        Ok(())
    }

    /// Get public payload, decrypt masked payload and verify signature with Author's public key.
    fn handle_signed_packet<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<(Trytes, Trytes)> {
        ensure!(self.author_mss_pk.is_some(), "No Author's MSS public key found, can't verify signature.");

        let mut content = signed_packet::ContentUnwrap::new(&self.store);
        content.unwrap(ctx)?;
        ensure!(self.author_mss_pk.as_ref().map_or(false, |mss_pk| *mss_pk == content.mss_pk), "Bad signed packet signature.");
        Ok((content.public_payload, content.masked_payload))
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    fn handle_tagged_packet<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<(Trytes, Trytes)> {
        let mut content = tagged_packet::ContentUnwrap::new(&self.store);
        content.unwrap(ctx)?;
        Ok((content.public_payload, content.masked_payload))
    }

    /// Unwrap message.
    pub fn handle_msg(&mut self, msg: &TrinaryMessage<Link>) -> Result<()> {
        if self.appinst.is_some() {
            ensure!(self.appinst.as_ref().unwrap().base() == msg.link().base(), "Bad message application instance.");
        }

        let mut ctx = unwrap::Context::new(msg.body.slice());
        let mut hdr = Header::<Link>::default();
        hdr.unwrap(&mut ctx)?;

        if (hdr.content_type.0).eq_str(announce::TYPE) {
            self.handle_announce(&mut ctx)?;
            Ok(())
        } else
        if (hdr.content_type.0).eq_str(change_key::TYPE) {
            self.handle_change_key(&mut ctx)?;
            Ok(())
        } else
        if (hdr.content_type.0).eq_str(keyload::TYPE) {
            self.handle_keyload(&mut ctx)?;
            Ok(())
        } else
        if (hdr.content_type.0).eq_str(signed_packet::TYPE) {
            self.handle_signed_packet(&mut ctx)?;
            Ok(())
        } else
        if (hdr.content_type.0).eq_str(tagged_packet::TYPE) {
            self.handle_tagged_packet(&mut ctx)?;
            Ok(())
        } else {
            bail!("Unsupported content type: '{}'.", (hdr.content_type.0).to_string())
        }
    }
}
