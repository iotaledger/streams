// Rust
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA
use crypto::keys::x25519;

// Streams
use lets::{address::Address, id::Identifier, message::Topic};

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
        let mut removed = false;
        self.0.iter_mut().for_each(|(_topic, branch)| {
            if branch.remove(id) {
                removed = true
            }
        });
        removed
    }

    pub(crate) fn move_branch(&mut self, old_topic: &Topic, new_topic: &Topic) -> bool {
        let old_branch = self.0.remove(old_topic);
        old_branch.map_or(false, |key_store| self.0.insert(new_topic.clone(), key_store).is_none())
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

    pub(crate) fn insert_cursor(&mut self, topic: &Topic, id: Identifier, cursor: usize) -> bool {
        self.get_branch_mut(topic)
            .map_or(false, |branch| branch.cursors.insert(id, cursor).is_none())
    }

    pub(crate) fn insert_key(&mut self, topic: &Topic, id: Identifier, xkey: x25519::PublicKey) -> bool {
        self.get_branch_mut(topic)
            .map_or(false, |branch| branch.keys.insert(id, xkey).is_none())
    }

    pub(crate) fn get_key(&self, topic: &Topic, identifier: &Identifier) -> Option<&x25519::PublicKey> {
        self.get_branch(topic)
            .ok()
            .and_then(|branch| branch.keys.get(identifier))
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
    anchor: Address,
    latest_link: Address,
}

impl KeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        self.cursors.remove(id).is_some() | self.keys.remove(id).is_some()
    }

    pub(crate) fn subscribers(&self) -> impl Iterator<Item = Identifier> + Clone + '_ {
        self.keys.keys().copied()
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
        writeln!(f, "\t* keys")?;
        for (id, key) in self.keys.iter() {
            writeln!(f, "\t\t{} => {:?}", id, key.as_ref())?;
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
            anchor: Address::default(),
            latest_link: Address::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BranchStore, KeyStore};
    use alloc::string::ToString;
    use lets::{
        id::{Ed25519, Identity},
        message::Topic,
    };

    #[test]
    fn branch_store_can_remove_a_cursor_from_all_branches_at_once() {
        let mut branch_store = BranchStore::new();
        let identifier = Identity::Ed25519(Ed25519::from_seed("identifier 1")).to_identifier();
        let topic_1 = Topic::new("topic 1".to_string());
        let topic_2 = Topic::new("topic 2".to_string());

        branch_store.insert_branch(topic_1.clone(), KeyStore::new());
        branch_store.insert_branch(topic_2.clone(), KeyStore::new());

        branch_store.insert_cursor(&topic_1, identifier, 10);
        branch_store.insert_cursor(&topic_2, identifier, 20);

        branch_store.remove_from_all(&identifier);

        assert!(!branch_store.is_cursor_tracked(&topic_1, &identifier));
        assert!(!branch_store.is_cursor_tracked(&topic_2, &identifier));
    }
}
