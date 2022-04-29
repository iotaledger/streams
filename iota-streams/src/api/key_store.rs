// Rust
use alloc::vec::Vec;
use core::{
    borrow::BorrowMut,
    fmt,
};

// 3rd-party
use hashbrown::HashMap;

// IOTA
use crypto::keys::x25519;

// Streams
use spongos::PRP;
use LETS::{
    id::{
        Identifier,
        Psk,
        PskId,
    },
    link::Cursor,
};

// Local

// use iota_streams_core::{
//     err,
//     prelude::{
//         HashMap,
//         Vec,
//     },
//     psk::Psk,
//     sponge::prp::PRP,
//     Errors::BadIdentifier,
//     Result,
// };

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeyStore {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional Cursor.
    // cursors: HashMap<Identifier, Cursor<Link>>,
    cursors: HashMap<Identifier, u64>,
    keys: HashMap<Identifier, x25519::PublicKey>,
    psks: HashMap<PskId, Psk>,
}

impl KeyStore {
    fn new() -> Self {
        Default::default()
    }
}

impl KeyStore {
    fn contains_subscriber(&self, id: &Identifier) -> bool {
        self.cursors.contains_key(id)
    }

    pub(crate) fn get_cursor(&self, id: &Identifier) -> Option<u64> {
        self.cursors.get(id).copied()
    }

    // fn get_cursor_mut(&mut self, id: &Identifier) -> Option<&mut Cursor<Link>> {
    //     self.cursors.get_mut(id)
    // }

    pub(crate) fn insert_cursor(&mut self, id: Identifier, cursor: u64) -> bool {
        self.cursors.insert(id, cursor).is_none()
    }

    pub(crate) fn insert_cursor_if_missing(&mut self, id: Identifier, cursor: u64) {
        if !self.cursors.contains_key(&id) {
            self.cursors.insert(id, cursor);
        }
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, u64)> + ExactSizeIterator + '_ {
        self.cursors.iter().map(|(identifier, cursor)| (*identifier, *cursor))
    }

    pub(crate) fn subscribers(&self) -> impl Iterator<Item = Identifier> + '_ {
        self.psks
            .keys()
            .copied()
            .map(Into::into)
            .chain(self.keys.keys().copied())
    }

    // fn replace_cursors(&mut self, new_cursor: Cursor<Link>)
    // where
    //     Link: Clone,
    // {
    //     for (_id, cursor) in self.cursors.iter_mut() {
    //         *cursor = new_cursor.clone()
    //     }
    // }

    fn contains_psk(&self, pskid: &PskId) -> bool {
        self.psks.contains_key(pskid)
    }

    fn get_psk(&self, pskid: &PskId) -> Option<&Psk> {
        self.psks.get(pskid)
    }

    pub(crate) fn get_x25519(&self, identifier: &Identifier) -> Option<&x25519::PublicKey> {
        self.keys.get(identifier)
    }

    pub(crate) fn insert_psk(&mut self, id: PskId, psk: Psk) -> bool {
        self.psks.insert(id, psk).is_none()
    }

    pub(crate) fn insert_key(&mut self, id: Identifier, xkey: x25519::PublicKey) -> bool {
        self.keys.insert(id, xkey).is_none()
    }

    pub(crate) fn get_exchange_key(&self, identifier: &Identifier) -> Option<&[u8]> {
        match identifier {
            Identifier::PskId(pskid) => self.psks.get(pskid).map(AsRef::as_ref),
            _ => self.keys.get(identifier).map(AsRef::as_ref),
        }
    }

    fn exchange_keys<'a, I>(&'a self, ids: I) -> impl Iterator<Item = (Identifier, &'a [u8])>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        ids.into_iter().filter_map(move |id| match &id {
            Identifier::PskId(pskid) => self
                .psks
                .get_key_value(pskid)
                .map(|(pskid, psk)| ((*pskid).into(), psk.as_bytes())),
            _ => self.keys.get_key_value(id).map(|(id, pk)| (*id, pk.as_slice())),
        })
    }

    fn all_exchange_keys(&self) -> impl Iterator<Item = (Identifier, &[u8])> {
        self.subscribers()
            .filter_map(move |identifier| Some((identifier, self.get_exchange_key(&identifier)?)))
    }

    // fn cursors(&self) -> impl Iterator<Item = (&Identifier, &Cursor<Link>)> {
    //     self.cursors.iter()
    // }

    // fn cursors_mut(&mut self) -> impl Iterator<Item = (&Identifier, &mut Cursor<Link>)> {
    //     self.cursors.iter_mut()
    // }

    fn num_cursors(&self) -> usize {
        self.cursors.len()
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        self.cursors.remove(id).is_some() && self.keys.remove(id).is_some() && {
            if let Identifier::PskId(pskid) = id {
                self.psks.remove(pskid).is_some()
            } else {
                true
            }
        }
    }

    pub(crate) fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.psks.remove(&pskid).is_some()
    }
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "cursors:")?;
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "\t<{}> => {}", id, cursor)?;
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
