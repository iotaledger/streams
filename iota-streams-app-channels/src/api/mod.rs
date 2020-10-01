use core::fmt;

use iota_streams_app::{
    message::{
        HasLink,
        LinkGenerator,
    },
    transport,
};
use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    psk,
    sponge::prp::PRP,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

#[cfg(all(feature = "tangle"))]
use iota_streams_app::transport::tangle::{
    DefaultTangleLinkGenerator,
    TangleAddress,
};

pub trait ChannelLinkGenerator<Link>
where
    Self: Default,
    Link: HasLink,
    // TODO: Combine these 4 implementations into one trait instead and call each method a meaningful name: `create_channel_instance`, `get_announce_msgid`, `reset_state`, `link_from`.
    for<'a> Self: LinkGenerator<Link, (&'a ed25519::PublicKey, u64)>
        + LinkGenerator<Link, Link>
        + LinkGenerator<Link, ()>
        + LinkGenerator<Link, (&'a <Link as HasLink>::Rel, &'a ed25519::PublicKey, u64)>,
{
}

pub struct SequencingState<Link>(pub Link, pub u64);

pub trait PublicKeyStore<Info>: Default {
    fn filter<'a>(&'a self, pks: &'a Vec<ed25519::PublicKey>) -> Vec<(&'a ed25519::PublicKey, &'a x25519::PublicKey)>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, pk: &ed25519::PublicKey) -> Option<&Info>;
    fn get_mut(&mut self, pk: &ed25519::PublicKey) -> Option<&mut Info>;
    fn get_ke_pk(&self, pk: &ed25519::PublicKey) -> Option<&x25519::PublicKey>;
    fn insert(&mut self, pk: ed25519::PublicKey, info: Info);
    fn keys(&self) -> Vec<(&ed25519::PublicKey, &x25519::PublicKey)>;
    fn iter(&self) -> Vec<(&ed25519::PublicKey, &Info)>;
    fn iter_mut(&mut self) -> Vec<(&ed25519::PublicKey, &mut Info)>;
}

pub struct PublicKeyMap<Info> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional info.
    pks: HashMap<ed25519::PublicKeyWrap, (x25519::PublicKey, Info)>,
}

impl<Info> PublicKeyMap<Info> {
    pub fn new() -> Self {
        Self { pks: HashMap::new() }
    }
}

impl<Info> Default for PublicKeyMap<Info> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Info> PublicKeyStore<Info> for PublicKeyMap<Info> {
    fn filter<'a>(&'a self, pks: &'a Vec<ed25519::PublicKey>) -> Vec<(&'a ed25519::PublicKey, &'a x25519::PublicKey)> {
        pks.iter()
            .filter_map(|pk| self.pks.get_key_value(pk.into()).map(|(e, (x, _))| (&e.0, x)))
            .collect()
    }

    fn get(&self, pk: &ed25519::PublicKey) -> Option<&Info> {
        self.pks.get(pk.into()).map(|(_x, i)| i)
    }
    fn get_mut(&mut self, pk: &ed25519::PublicKey) -> Option<&mut Info> {
        self.pks.get_mut(pk.into()).map(|(_x, i)| i)
    }
    fn get_ke_pk(&self, pk: &ed25519::PublicKey) -> Option<&x25519::PublicKey> {
        self.pks.get(pk.into()).map(|(x, _i)| x)
    }
    fn insert(&mut self, pk: ed25519::PublicKey, info: Info) {
        let xpk = x25519::public_from_ed25519(&pk);
        self.pks.insert(pk.into(), (xpk, info));
    }
    fn keys(&self) -> Vec<(&ed25519::PublicKey, &x25519::PublicKey)> {
        self.pks.iter().map(|(k, (x, _i))| (&k.0, x)).collect()
    }
    fn iter(&self) -> Vec<(&ed25519::PublicKey, &Info)> {
        self.pks.iter().map(|(k, (_x, i))| (&k.0, i)).collect()
    }
    fn iter_mut(&mut self) -> Vec<(&ed25519::PublicKey, &mut Info)> {
        self.pks.iter_mut().map(|(k, (_x, i))| (&k.0, i)).collect()
    }
}

impl<Info: fmt::Display> fmt::Display for PublicKeyMap<Info> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, (_x, i)) in self.pks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(k.0.as_bytes()), i)?;
        }
        Ok(())
    }
}

pub trait PresharedKeyStore: Default {
    fn filter<'a>(&'a self, psk_ids: &'_ psk::PskIds) -> Vec<psk::IPsk<'a>>;
    fn get<'a>(&'a self, pskid: &'_ psk::PskId) -> Option<&'a psk::Psk>;
    fn iter(&self) -> Vec<(&psk::PskId, &psk::Psk)>;
}

#[derive(Default)]
pub struct PresharedKeyMap {
    psks: HashMap<psk::PskId, psk::Psk>,
}

impl PresharedKeyStore for PresharedKeyMap {
    fn filter<'a>(&'a self, psk_ids: &'_ psk::PskIds) -> Vec<psk::IPsk<'a>> {
        psk_ids
            .iter()
            .filter_map(|psk_id| self.psks.get_key_value(psk_id))
            .collect()
    }
    fn get<'a>(&'a self, pskid: &'_ psk::PskId) -> Option<&'a psk::Psk> {
        self.psks.get(pskid)
    }
    fn iter(&self) -> Vec<(&psk::PskId, &psk::Psk)> {
        self.psks.iter().collect()
    }
}

pub mod user;

#[cfg(all(feature = "tangle"))]
impl<F> ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator<F> where F: PRP {}

/// Tangle-specific Channel API.
#[cfg(all(feature = "tangle"))]
pub mod tangle;
