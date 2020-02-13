//! Customize Author with default implementation for use over the Tangle.

use failure::bail;
use std::str::FromStr;
use iota_mam_core::{prng, trits::Trits};
use iota_mam_protobuf3::types::Trytes;
use crate::core::{*, msg::{*, header::Header}};
use crate::channel::api::{*, author::*};
use crate::Result;
use super::*;

/// Author type.
pub struct Author {
    imp: AuthorT<Address, Store, LinkGen>,
}

impl Author {
    pub fn new(seed: &str, mss_height: usize, with_ntru: bool) -> Self {
        let nonce = Trits::from_str("TANGLEAUTHOR").unwrap();
        Self {
            imp: AuthorT::gen(Store::default(), LinkGen::default(), prng::dbg_init_str(seed), &nonce, mss_height, with_ntru),
        }
    }

    pub fn announce(&mut self) -> Result<Message> {
        self.imp.announce(MsgInfo::Announce)
    }

    pub fn change_key(&mut self, link_to: &Address) -> Result<Message> {
        self.imp.change_key(link_to.rel(), MsgInfo::ChangeKey)
    }

    pub fn share_keyload(&mut self, link_to: &Address, psk_ids: &PskIds, ntru_pkids: &NtruPkids) -> Result<Message> {
        /*
        self.imp.share_keyload(link_to.rel(), psk_ids, ntru_pkids, MsgInfo::Keyload)
         */
        bail!("share_keyload not implemented")
    }

    pub fn share_keyload_for_everyone(&mut self, link_to: &Address) -> Result<Message> {
        /*
        self.imp.share_keyload(link_to.rel(), psk_ids, ntru_pkids, MsgInfo::Keyload)
         */
        bail!("share_keyload not implemented")
    }

    pub fn sign_packet(&mut self, link_to: &Address, public_payload: &Trytes, masked_payload: &Trytes) -> Result<Message> {
        self.imp.sign_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::SignedPacket)
    }

    pub fn tag_packet(&mut self, link_to: &Address, public_payload: &Trytes, masked_payload: &Trytes) -> Result<Message> {
        self.imp.tag_packet(link_to.rel(), public_payload, masked_payload, MsgInfo::TaggedPacket)
    }

}
