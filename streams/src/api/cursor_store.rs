// Rust
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA

// Streams
use lets::{address::MsgId, id::Identifier, message::Topic};
use lets::id::Permissioned;

// Local

#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct CursorStore(HashMap<Topic, InnerCursorStore>);

impl CursorStore {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn new_branch(&mut self, topic: Topic) -> bool {
        self.0.insert(topic, InnerCursorStore::default()).is_none()
    }

    pub(crate) fn topics(&self) -> impl Iterator<Item = &Topic> + ExactSizeIterator {
        self.0.keys()
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        let removals = self.0.values_mut().flat_map(|branch| {
            branch
                .cursors
                .iter()
                .find(|(p, _)| p.identifier() == id)
                .and_then(|(perm, _)| Some(perm.clone()))
                .and_then(|perm| branch.cursors.remove(&perm))
        });
        removals.count() > 0
    }

    pub(crate) fn get_permission(&self, topic: &Topic, id: &Identifier) -> Option<&Permissioned<Identifier>> {
        self.0
            .get(topic)
            .and_then(|branch|
                branch
                    .cursors
                    .iter()
                    .find(|c| c.0.identifier() == id)
                    .and_then(|(perm, _)| Some(perm))
            )
    }

    /*pub(crate) fn change_permission(&mut self, topic: &Topic, permission: &Permissioned<Identifier>) -> bool {
        self.0
            .get_mut(topic)
            .and_then(|branch| {
                if let Some((stored_perm, stored_cursor)) = branch
                    .cursors
                    .iter()
                    .find(|c| c.0.identifier() == permission.identifier())
                    .and_then(|(perm, cursor)| Some((perm.clone(), cursor.clone())))
                {
                    branch.cursors.remove(&stored_perm);
                    branch.cursors.insert(permission.clone(), stored_cursor)
                } else {
                    None
                }
            })
            .is_some()
    }*/

    pub(crate) fn get_cursor(&self, topic: &Topic, id: &Identifier) -> Option<usize> {
        self.0.get(topic).and_then(|branch|
            branch
                .cursors
                .iter()
                .find(|c| c.0.identifier() == id)
                .map(|(_, cursor)| cursor)
                .copied()
        )
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (&Topic, &Permissioned<Identifier>, usize)> + Clone + '_ {
        self.0
            .iter()
            .flat_map(|(topic, branch)| branch.cursors.iter().map(move |(id, cursor)| (topic, id, *cursor)))
    }

    pub(crate) fn insert_cursor(&mut self, topic: &Topic, id: Permissioned<Identifier>, cursor: usize) -> Option<usize> {
        let mut removed = false;
        // If new permission does not match old permission, remove old permission before inserting
        if let Some(perm) = self.get_permission(topic, id.identifier()) {
            if perm != &id {
                removed = self.remove(id.identifier());
            }
        }

        self.0.get_mut(topic)
            .and_then(|branch| branch.cursors.insert(id, cursor))
    }

    pub(crate) fn set_latest_link(&mut self, topic: &Topic, latest_link: MsgId) -> Option<InnerCursorStore> {
        match self.0.get_mut(topic) {
            Some(branch) => {
                branch.latest_link = latest_link;
                None
            }
            None => {
                let branch = InnerCursorStore {
                    latest_link,
                    ..Default::default()
                };
                self.0.insert(topic.clone(), branch)
            }
        }
    }

    pub(crate) fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.0.get(topic).map(|branch| branch.latest_link)
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct InnerCursorStore {
    cursors: HashMap<Permissioned<Identifier>, usize>,
    latest_link: MsgId,
}

impl fmt::Debug for InnerCursorStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\t* latest link: {}", self.latest_link)?;
        writeln!(f, "\t* cursors:")?;
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "\t\t{:?} => {}", id, cursor)?;
        }
        Ok(())
    }
}

impl fmt::Debug for CursorStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "* branches:")?;
        for (topic, branch) in &self.0 {
            writeln!(f, "{:?} => \n{:?}", topic, branch)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CursorStore;
    use alloc::string::ToString;
    use lets::{
        id::{Ed25519, Identity},
        message::Topic,
    };

    #[test]
    fn branch_store_can_remove_a_cursor_from_all_branches_at_once() {
        let mut branch_store = CursorStore::new();
        let identifier = Identity::Ed25519(Ed25519::from_seed("identifier 1")).to_identifier();
        let topic_1 = Topic::new("topic 1".to_string());
        let topic_2 = Topic::new("topic 2".to_string());

        branch_store.new_branch(topic_1.clone());
        branch_store.new_branch(topic_2.clone());

        branch_store.insert_cursor(&topic_1, identifier.clone(), 10);
        branch_store.insert_cursor(&topic_2, identifier.clone(), 20);

        branch_store.remove(&identifier);

        assert!(!branch_store.is_cursor_tracked(&topic_1, &identifier));
        assert!(!branch_store.is_cursor_tracked(&topic_2, &identifier));
    }
}
