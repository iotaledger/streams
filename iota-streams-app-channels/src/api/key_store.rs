use core::{
    borrow::BorrowMut,
    convert::TryInto,
    fmt,
};

use crypto::keys::x25519;

use iota_streams_app::id::identifier::Identifier;
#[cfg(feature = "did")]
use iota_streams_core::Errors::UnsupportedIdentifier;
use iota_streams_core::{
    err,
    prelude::{
        HashMap,
        Vec,
    },
    psk::Psk,
    sponge::prp::PRP,
    Errors::BadIdentifier,
    Result,
};

pub trait KeyStore<Info: Clone, F: PRP>: Default {
    fn filter<'a, I>(&self, ids: I) -> Vec<(&Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, id: &Identifier) -> Option<&Info>;
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info>;
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey>;
    fn get_psk(&self, id: &Identifier) -> Option<Psk>;
    fn contains(&self, id: &Identifier) -> bool;
    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()>;
    fn replace_cursors(&mut self, info: Info) -> Result<()>;
    #[cfg(feature = "did")]
    fn insert_did(&mut self, id: Identifier, xkey: x25519::PublicKey, info: Info) -> Result<()>;
    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()>;
    fn keys(&self) -> Vec<(&Identifier, Vec<u8>)>;
    fn iter(&self) -> Vec<(&Identifier, &Info)>;
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)>;
    fn remove(&mut self, id: &Identifier);
}

pub struct KeyMap<Info> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional info.
    ke_pks: HashMap<Identifier, (x25519::PublicKey, Info)>,
    psks: HashMap<Identifier, (Option<Psk>, Info)>,
}

impl<Info> KeyMap<Info> {
    pub fn new() -> Self {
        Self {
            ke_pks: HashMap::new(),
            psks: HashMap::new(),
        }
    }
}

impl<Info> Default for KeyMap<Info> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Info: Clone, F: PRP> KeyStore<Info, F> for KeyMap<Info> {
    fn filter<'a, I>(&self, ids: I) -> Vec<(&Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        ids.into_iter()
            .filter_map(|id| match &id {
                Identifier::EdPubKey(_id) => self
                    .ke_pks
                    .get_key_value(id)
                    .map(|(e, (x, _))| (e, x.as_slice().to_vec())),
                Identifier::PskId(_id) => self
                    .psks
                    .get_key_value(id)
                    .map(|(e, (x, _))| x.map(|xx| (e, xx.to_vec())))
                    .flatten(),
                #[cfg(feature = "did")]
                _ => self
                    .ke_pks
                    .get_key_value(id)
                    .map(|(e, (x, _))| (e, x.to_bytes().to_vec())),
            })
            .collect()
    }

    fn get(&self, id: &Identifier) -> Option<&Info> {
        match id {
            Identifier::PskId(_id) => self.psks.get(id).map(|(_x, i)| i),
            _ => self.ke_pks.get(id).map(|(_x, i)| i),
        }
    }
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info> {
        match id {
            Identifier::PskId(_id) => self.psks.get_mut(id).map(|(_x, i)| i),
            _ => self.ke_pks.get_mut(id).map(|(_x, i)| i),
        }
    }
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey> {
        match id {
            Identifier::PskId(_) => None,
            _ => self.ke_pks.get(id).map(|(x, _i)| x),
        }
    }

    fn get_psk(&self, id: &Identifier) -> Option<Psk> {
        match id {
            Identifier::PskId(_id) => match self.psks.get(id).map(|(x, _i)| *x) {
                Some(psk) => psk,
                None => None,
            },
            _ => None,
        }
    }

    fn contains(&self, id: &Identifier) -> bool {
        self.ke_pks.contains_key(id) || self.psks.contains_key(id)
    }

    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()> {
        match &id {
            Identifier::EdPubKey(pk) => {
                let store_id = pk.try_into()?;
                self.ke_pks.insert(id, (store_id, info));
                Ok(())
            }
            Identifier::PskId(_id) => {
                // not using the entry API to avoid having to pull the Default bound on Info
                // We cannot just use insert, as we don't have the Option<Psk>
                if let Some((_, old_info)) = self.psks.get_mut(&id) {
                    *old_info = info;
                } else {
                    self.psks.insert(id, (None, info));
                }
                Ok(())
            }
            #[cfg(feature = "did")]
            _ => err(UnsupportedIdentifier),
        }
    }

    fn replace_cursors(&mut self, info: Info) -> Result<()> {
        for (_id, cursor) in self.ke_pks.iter_mut() {
            cursor.1 = info.clone()
        }

        for (_pskid, cursor) in self.psks.iter_mut() {
            cursor.1 = info.clone()
        }
        Ok(())
    }

    #[cfg(feature = "did")]
    fn insert_did(&mut self, id: Identifier, xkey: x25519::PublicKey, info: Info) -> Result<()> {
        match &id {
            Identifier::DID(_id) => {
                self.ke_pks.insert(id, (xkey, info));
                Ok(())
            }
            _ => err(UnsupportedIdentifier),
        }
    }

    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()> {
        match &id {
            Identifier::PskId(_id) => {
                self.psks.insert(id, (psk, info));
                Ok(())
            }
            _ => err(BadIdentifier),
        }
    }

    fn keys(&self) -> Vec<(&Identifier, Vec<u8>)> {
        let mut keys: Vec<(&Identifier, Vec<u8>)> = self
            .ke_pks
            .iter()
            .map(|(k, (x, _i))| (k, x.as_slice().to_vec()))
            .collect();

        let psks: Vec<(&Identifier, Vec<u8>)> = self
            .psks
            .iter()
            .filter_map(|(k, (x, _i))| x.map(|x| (k, x.to_vec())))
            .collect();

        keys.extend(psks);
        keys
    }

    fn iter(&self) -> Vec<(&Identifier, &Info)> {
        let mut keys: Vec<(&Identifier, &Info)> = self.ke_pks.iter().map(|(k, (_x, i))| (k, i)).collect();

        let psks: Vec<(&Identifier, &Info)> = self.psks.iter().map(|(k, (_x, i))| (k, i)).collect();

        keys.extend(psks);
        keys
    }
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)> {
        let mut ke_pks: Vec<(&Identifier, &mut Info)> = self.ke_pks.iter_mut().map(|(k, (_x, i))| (k, i)).collect();

        let psks: Vec<(&Identifier, &mut Info)> = self.psks.iter_mut().map(|(k, (_x, i))| (k, i)).collect();

        ke_pks.extend(psks);
        ke_pks
    }

    fn remove(&mut self, id: &Identifier) {
        self.ke_pks.borrow_mut().remove(id);
        self.psks.borrow_mut().remove(id);
    }
}

impl<Info: fmt::Display> fmt::Display for KeyMap<Info> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, (_x, i)) in self.ke_pks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.to_bytes()), i)?;
        }
        for (k, (_x, i)) in self.psks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.to_bytes()), i)?;
        }
        Ok(())
    }
}
