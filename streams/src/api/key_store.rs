// Rust
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA
use crypto::keys::x25519;

// Streams
use lets::{
    address::Address,
    id::{Identifier, Psk, PskId},
    message::Topic,
};

// Local

#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct BranchStore(HashMap<Topic, KeyStore>);

impl BranchStore {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn new_branch(&mut self, topic: Topic) -> bool {
        self.0.insert(topic, KeyStore::default()).is_none()
    }

    pub(crate) fn topics(&self) -> Vec<&Topic> {
        self.0.keys().collect()
    }

    pub(crate) fn is_cursor_tracked(&self, topic: &Topic, id: &Identifier) -> bool {
        self.get_branch(topic)
            .map_or(false, |branch| branch.cursors.contains_key(id))
    }

    pub(crate) fn remove_from_all(&mut self, id: &Identifier) -> bool {
        self.0
            .iter_mut()
            .fold(false, |acc, (_topic, branch)| acc || branch.remove(id))
    }

    pub(crate) fn remove_psk_from_all(&mut self, pskid: PskId) -> bool {
        self.0
            .iter_mut()
            .fold(false, |acc, (_topic, branch)| acc || branch.remove_psk(pskid))
    }

    pub(crate) fn insert_branch(&mut self, topic: Topic, branch: KeyStore) -> bool {
        self.0.insert(topic, branch).is_none()
    }

    pub(crate) fn get_branch(&self, topic: &Topic) -> Result<&KeyStore> {
        self.0.get(topic).ok_or_else(|| anyhow!("Branch not found in store"))
    }

    pub(crate) fn get_branch_mut(&mut self, topic: &Topic) -> Result<&mut KeyStore> {
        self.0
            .get_mut(topic)
            .ok_or_else(|| anyhow!("Branch not found in store"))
    }

    pub(crate) fn get_cursor(&self, topic: &Topic, id: &Identifier) -> Option<usize> {
        self.get_branch(topic)
            .ok()
            .and_then(|branch| branch.cursors.get(id).copied())
    }

    pub(crate) fn cursors(
        &self,
        topic: &Topic,
    ) -> Result<impl Iterator<Item = (Identifier, usize)> + ExactSizeIterator + Clone + '_> {
        self.get_branch(topic)
            .map(|branch| branch.cursors.iter().map(|(identifier, cursor)| (*identifier, *cursor)))
    }

    pub(crate) fn keys(
        &self,
        topic: &Topic,
    ) -> Result<impl Iterator<Item = (Identifier, x25519::PublicKey)> + ExactSizeIterator + Clone + '_> {
        self.get_branch(topic)
            .map(|branch| branch.keys.iter().map(|(identifier, key)| (*identifier, *key)))
    }

    pub(crate) fn psks(
        &self,
        topic: &Topic,
    ) -> Result<impl Iterator<Item = (PskId, Psk)> + ExactSizeIterator + Clone + '_> {
        self.get_branch(topic)
            .map(|branch| branch.psks.iter().map(|(pskid, psk)| (*pskid, *psk)))
    }

    pub(crate) fn insert_cursor(&mut self, topic: &Topic, id: Identifier, cursor: usize) -> bool {
        self.get_branch_mut(topic)
            .map_or(false, |branch| branch.cursors.insert(id, cursor).is_none())
    }

    pub(crate) fn insert_key(&mut self, topic: &Topic, id: Identifier, xkey: x25519::PublicKey) -> bool {
        self.get_branch_mut(topic)
            .map_or(false, |branch| branch.keys.insert(id, xkey).is_none())
    }

    pub(crate) fn insert_psk(&mut self, topic: &Topic, id: PskId, psk: Psk) -> bool {
        self.get_branch_mut(topic)
            .map_or(false, |branch| branch.psks.insert(id, psk).is_none())
    }

    pub(crate) fn get_key(&self, topic: &Topic, identifier: &Identifier) -> Option<&x25519::PublicKey> {
        self.get_branch(topic)
            .ok()
            .and_then(|branch| branch.keys.get(identifier))
    }

    pub(crate) fn get_exchange_key(&self, topic: &Topic, identifier: &Identifier) -> Option<&[u8]> {
        self.get_branch(topic).ok().and_then(|branch| match identifier {
            Identifier::PskId(pskid) => branch.psks.get(pskid).map(AsRef::as_ref),
            _ => branch.keys.get(identifier).map(AsRef::as_ref),
        })
    }

    pub(crate) fn set_anchor(&mut self, topic: &Topic, anchor: Address) -> Result<()> {
        self.get_branch_mut(topic).map(|branch| branch.anchor = anchor)
    }

    pub(crate) fn set_latest_link(&mut self, topic: &Topic, latest_link: Address) -> Result<()> {
        self.get_branch_mut(topic)
            .map(|branch| branch.latest_link = latest_link)
    }

    pub(crate) fn get_anchor(&self, topic: &Topic) -> Result<Address> {
        self.get_branch(topic).map(|branch| branch.anchor)
    }

    pub(crate) fn get_latest_link(&self, topic: &Topic) -> Result<Address> {
        self.get_branch(topic).map(|branch| branch.latest_link)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeyStore {
    cursors: HashMap<Identifier, usize>,
    keys: HashMap<Identifier, x25519::PublicKey>,
    psks: HashMap<PskId, Psk>,
    anchor: Address,
    latest_link: Address,
}

impl KeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.psks.remove(&pskid).is_some()
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
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\t* anchor: {}", self.anchor)?;
        writeln!(f, "\t* latest link: {}", self.latest_link.relative())?;
        writeln!(f, "\t* cursors:")?;
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "\t\t{} => {}", id, cursor)?;
        }
        writeln!(f, "\t* PSKs:")?;
        for pskid in self.psks.keys() {
            writeln!(f, "\t\t<{:x}>", pskid)?;
        }
        Ok(())
    }
}

impl fmt::Debug for BranchStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "* branches:")?;
        for topic in self.topics() {
            writeln!(f, "{:?} => \n{:?}", topic, self.get_branch(topic).unwrap())?;
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
            anchor: Address::default(),
            latest_link: Address::default(),
        }
    }
}
