use std::collections::HashMap;
use std::collections::hash_map;
use iota_mam_core::{signature::mss, key_encapsulation::ntru, psk};

use crate::core::{HasLink, LinkGenerator};
use crate::core::transport::tangle::{TangleAddress, DefaultTangleLinkGenerator};

pub trait ChannelLinkGenerator<Link> where
    Link: HasLink,
    Self: LinkGenerator<Link, mss::PublicKey> + LinkGenerator<Link, <Link as HasLink>::Rel>
{}
impl ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator {}

pub mod author;
pub mod subscriber;
pub mod tangle;

pub type Psks = HashMap<psk::PskId, psk::Psk>;
pub type IPsks<'a> = hash_map::Iter<'a, &'a psk::PskId, &'a psk::Psk>;
pub type PskIds = Vec<psk::PskId>;
    
pub(crate) fn filter_psks<'a>(psks: &'a Psks, pskids: &'_ PskIds) -> Vec<(&'a psk::PskId, &'a psk::Psk)> {
    psks
       .iter()
       .filter(|(k,v)| pskids.iter().find(|pskid| **pskid == **k).is_some())
       .collect::<Vec<(&psk::PskId, &psk::Psk)>>()
}

pub type NtruPks = HashMap<ntru::Pkid, ntru::PublicKey>;
pub type INtruPks<'a> = hash_map::Iter<'a, &'a ntru::Pkid, &'a ntru::PublicKey>;
pub type NtruPkids = Vec<ntru::Pkid>;

pub(crate) fn filter_ntru_pks<'a>(ntru_pks: &'a NtruPks, ntru_pkids: &'_ NtruPkids) -> Vec<(&'a ntru::Pkid, &'a ntru::PublicKey)> {
    ntru_pks
       .iter()
       .filter(|(k,v)| ntru_pkids.iter().find(|ntru_pkid| **ntru_pkid == **k).is_some())
       .collect::<Vec<(&ntru::Pkid, &ntru::PublicKey)>>()
}
