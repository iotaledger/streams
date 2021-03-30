use core::fmt;
use iota_streams_core::Result;

use iota_streams_core::prelude::{
    HashMap,
    Vec,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

pub trait PublicKeyStore<Info>: Default {
    fn filter<'a>(&'a self, pks: &'a [ed25519::PublicKey]) -> Vec<(&'a ed25519::PublicKey, &'a x25519::PublicKey)>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, pk: &ed25519::PublicKey) -> Option<&Info>;
    fn get_mut(&mut self, pk: &ed25519::PublicKey) -> Option<&mut Info>;
    fn get_ke_pk(&self, pk: &ed25519::PublicKey) -> Option<&x25519::PublicKey>;
    fn insert(&mut self, pk: ed25519::PublicKey, info: Info) -> Result<()>;
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
    fn filter<'a>(&'a self, pks: &'a [ed25519::PublicKey]) -> Vec<(&'a ed25519::PublicKey, &'a x25519::PublicKey)> {
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
    fn insert(&mut self, pk: ed25519::PublicKey, info: Info) -> Result<()> {
        let xpk = x25519::public_from_ed25519(&pk)?;
        self.pks.insert(pk.into(), (xpk, info));
        Ok(())
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
