use core::{
    borrow::BorrowMut,
    fmt,
};

use crypto::keys::x25519;
use crypto::keys::x25519::PublicKey;

use iota_streams_app::id::identifier::Identifier;
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
use iota_streams_core::psk::PskId;

pub trait KeyStore<Cursor, F: PRP>: Default {
    fn filter<'a, I>(&self, ids: I) -> Vec<(Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>;

    fn cursors(&self) -> &HashMap<Identifier, Cursor>;
    fn cursors_mut(&mut self) -> &mut HashMap<Identifier, Cursor>;
    fn psks(&self) -> &HashMap<PskId, Psk>;

    fn replace_cursors(&mut self, cursor: Cursor) -> Result<()> where Cursor: Clone;
    fn insert_psk(&mut self, id: Identifier, psk: Psk) -> Result<()>;
    fn insert_keys(&mut self, id: Identifier, xkey: x25519::PublicKey) -> Result<()>;

    fn keys(&self) -> Vec<(Identifier, Vec<u8>)>;
    fn iter(&self) -> Vec<(&Identifier, &Cursor)>;
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Cursor)>;
    fn remove(&mut self, id: &Identifier);
}

pub struct KeyMap<Cursor> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional Cursor.
    cursors: HashMap<Identifier, Cursor>,
    keys: HashMap<Identifier, x25519::PublicKey>,
    psks: HashMap<PskId, Psk>,
}

impl<Cursor> KeyMap<Cursor> {
    pub fn new() -> Self {
        Self {
            cursors: HashMap::new(),
            keys: HashMap::new(),
            psks: HashMap::new(),
        }
    }
}

impl<Cursor> Default for KeyMap<Cursor> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Cursor, F: PRP> KeyStore<Cursor, F> for KeyMap<Cursor> {
    fn filter<'a, I>(&self, ids: I) -> Vec<(Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        ids.into_iter()
            .filter_map(|id| match &id {
                Identifier::PskId(pskid) => self
                    .psks
                    .get_key_value(pskid)
                    .map(|(pskid, psk)| ((*pskid).into(), psk.to_vec())),
                _ => self
                    .keys
                    .get_key_value(id)
                    .map(|(id, pk)| (*id, pk.as_slice().to_vec())),
            })
            .collect()
    }

    fn cursors(&self) -> &HashMap<Identifier, Cursor> {
        &self.cursors
    }

    fn cursors_mut(&mut self) -> &mut HashMap<Identifier, Cursor> {
        &mut self.cursors
    }

    fn psks(&self) -> &HashMap<PskId, Psk> {
        &self.psks
    }

    fn replace_cursors(&mut self, new_cursor: Cursor) -> Result<()> where Cursor: Clone {
        for (_id, cursor) in self.cursors.iter_mut() {
            *cursor = new_cursor.clone()
        }
        Ok(())
    }

    fn insert_psk(&mut self, id: Identifier, psk: Psk) -> Result<()> {
        match &id {
            Identifier::PskId(pskid) => {
                self.psks.insert(*pskid, psk);
                Ok(())
            }
            _ => err(BadIdentifier),
        }
    }

    fn insert_keys(&mut self, id: Identifier, xkey: PublicKey) -> Result<()> {
        if !self.keys.contains_key(&id) {
            self.keys.insert(id, xkey);
        }
        Ok(())
    }

    fn keys(&self) -> Vec<(Identifier, Vec<u8>)> {
        let mut keys: Vec<(Identifier, Vec<u8>)> = self
            .keys
            .iter()
            .map(|(id, pk)| (*id, pk.as_slice().to_vec()))
            .collect();

        let psks: Vec<(Identifier, Vec<u8>)> = self
            .psks
            .iter()
            .map(|(id, psk)| ((*id).into(), psk.to_vec()))
            .collect();

        keys.extend(psks);
        keys
    }

    fn iter(&self) -> Vec<(&Identifier, &Cursor)> {
        self.cursors.iter().map(|(id, cursor)| (id, cursor)).collect()
    }
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Cursor)> {
        self.cursors.iter_mut().map(|(id, cursor)| (id, cursor)).collect()
    }

    fn remove(&mut self, id: &Identifier) {
        self.cursors.borrow_mut().remove(id);
        self.keys.borrow_mut().remove(id);
        if let Identifier::PskId(pskid) = id {
            self.psks.borrow_mut().remove(pskid);
        }
    }
}

impl<Cursor: fmt::Display> fmt::Display for KeyMap<Cursor> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&id.to_bytes()), cursor)?;
        }
        Ok(())
    }
}
