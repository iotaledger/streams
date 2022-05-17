// Rust
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA
use crypto::keys::x25519;

// Streams
use lets::id::{Identifier, Psk, PskId};

// Local

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeyStore {
    cursors: HashMap<Identifier, usize>,
    keys: HashMap<Identifier, x25519::PublicKey>,
    psks: HashMap<PskId, Psk>,
}

impl KeyStore {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn is_cursor_tracked(&self, id: &Identifier) -> bool {
        self.cursors.contains_key(id)
    }

    pub(crate) fn get_cursor(&self, id: &Identifier) -> Option<usize> {
        self.cursors.get(id).copied()
    }

    pub(crate) fn insert_cursor(&mut self, id: Identifier, cursor: usize) -> bool {
        self.cursors.insert(id, cursor).is_none()
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, usize)> + ExactSizeIterator + Clone + '_ {
        self.cursors.iter().map(|(identifier, cursor)| (*identifier, *cursor))
    }

    pub(crate) fn get_key(&self, identifier: &Identifier) -> Option<&x25519::PublicKey> {
        self.keys.get(identifier)
    }

    pub(crate) fn insert_key(&mut self, id: Identifier, xkey: x25519::PublicKey) -> bool {
        self.keys.insert(id, xkey).is_none()
    }

    pub(crate) fn keys(
        &self,
    ) -> impl Iterator<Item = (Identifier, x25519::PublicKey)> + ExactSizeIterator + Clone + '_ {
        self.keys.iter().map(|(identifier, key)| (*identifier, *key))
    }

    pub(crate) fn insert_psk(&mut self, id: PskId, psk: Psk) -> bool {
        self.psks.insert(id, psk).is_none()
    }

    pub(crate) fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.psks.remove(&pskid).is_some()
    }

    pub(crate) fn psks(&self) -> impl Iterator<Item = (PskId, Psk)> + ExactSizeIterator + Clone + '_ {
        self.psks.iter().map(|(pskid, psk)| (*pskid, *psk))
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        self.cursors.remove(id).is_some() | self.keys.remove(id).is_some()
    }

    pub(crate) fn subscribers(&self) -> impl Iterator<Item = Identifier> + Clone + '_ {
        self.psks
            .keys()
            .copied()
            .map(Into::into)
            .chain(self.keys.keys().copied())
    }

    pub(crate) fn get_exchange_key(&self, identifier: &Identifier) -> Option<&[u8]> {
        match identifier {
            Identifier::PskId(pskid) => self.psks.get(pskid).map(AsRef::as_ref),
            _ => self.keys.get(identifier).map(AsRef::as_ref),
        }
    }
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "* cursors:")?;
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "\t{:?} => {}", id, cursor)?;
        }
        writeln!(f, "* PSKs:")?;
        for pskid in self.psks.keys() {
            writeln!(f, "\t<{:x}>", pskid)?;
        }
        Ok(())
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self {
            cursors: HashMap::new(),
            keys: HashMap::new(),
            psks: HashMap::new(),
        }
    }
}
