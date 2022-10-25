// Rust
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA

// Streams
use lets::{
    address::MsgId,
    id::{Identifier, Permissioned},
    message::Topic,
};

// Local

/// Mapping of [`Topic`] to [`InnerCursorStore`]
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct CursorStore(HashMap<Topic, InnerCursorStore>);

impl CursorStore {
    /// Cretes a default mapping
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Inserts a new [`InnerCursorStore`] mapped to [`Topic`]
    ///
    /// # Arguments
    /// * `topic`: Identifier for branch
    pub(crate) fn new_branch(&mut self, topic: Topic) -> bool {
        self.0.insert(topic, InnerCursorStore::default()).is_none()
    }

    /// Remove the cursors with the given identifier from the map, returning true if the cursor was
    /// found and removed.
    ///
    /// # Arguments
    /// * `id`: The identifier to be removed from [`InnerCursorStore`].
    ///
    /// Returns:
    /// Success of removal.
    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        let removals = self.0.values_mut().flat_map(|branch| {
            branch
                .cursors
                .iter()
                .find(|(p, _)| p.identifier() == id)
                .map(|(perm, _)| perm.clone())
                .and_then(|perm| branch.cursors.remove(&perm))
        });
        removals.count() > 0
    }

    /// Given a [`Topic`] and an [`Identifier`], return the [`Permissioned`] [`Identifier`] if it
    /// exists
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch that the cursor is stored in.
    /// * `id`: The identifier of the cursor to get.
    ///
    /// Returns:
    /// A reference to a [`Permissioned`]<[`Identifier`]>
    pub(crate) fn get_permission(&self, topic: &Topic, id: &Identifier) -> Option<&Permissioned<Identifier>> {
        self.0.get(topic).and_then(|branch| {
            branch
                .cursors
                .iter()
                .find(|c| c.0.identifier() == id)
                .map(|(perm, _)| perm)
        })
    }

    /// Given a [`Topic`] and an [`Identifier`], return the cursor if it exists
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch that the cursor is stored in.
    /// * `id`: The identifier of the cursor to get.
    ///
    /// Returns:
    /// A cursor.
    pub(crate) fn get_cursor(&self, topic: &Topic, id: &Identifier) -> Option<usize> {
        self.0.get(topic).and_then(|branch| {
            branch
                .cursors
                .iter()
                .find(|c| c.0.identifier() == id)
                .map(|(_, cursor)| cursor)
                .copied()
        })
    }

    /// Returns an iterator over all the cursors in the tree
    pub(crate) fn cursors(&self) -> impl Iterator<Item = (&Topic, &Permissioned<Identifier>, usize)> + Clone + '_ {
        self.0
            .iter()
            .flat_map(|(topic, branch)| branch.cursors.iter().map(move |(id, cursor)| (topic, id, *cursor)))
    }

    /// Given a [`Topic`], return an iterator over the cursors for that topic, if any.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch that the cursor is stored in.
    ///
    /// Returns:
    /// An iterator over the cursors for a given topic.
    pub(crate) fn cursors_by_topic(
        &self,
        topic: &Topic,
    ) -> Option<impl Iterator<Item = (&Permissioned<Identifier>, &usize)>> {
        self.0.get(topic).map(|inner| inner.cursors.iter())
    }

    /// If the [`Permissioned`] [`Identifier`] is already in the map, and the permission is
    /// different, remove the old permission and keep the old cursor. Otherwise, insert the new
    /// permission and cursor
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch that the cursor is stored in.
    /// * `id`: The [`Permissioned`] [`Identifier`] that the cursor will be mapped to.
    /// * `cursor`: The publisher cursor to be stored.
    ///
    /// Returns:
    /// The old cursor value, if any.
    pub(crate) fn insert_cursor(
        &mut self,
        topic: &Topic,
        id: Permissioned<Identifier>,
        cursor: usize,
    ) -> Option<usize> {
        // If new permission does not match old permission, remove old permission before inserting, and keep
        // old cursor
        let cursor = match self.get_permission(topic, id.identifier()) {
            Some(perm) => {
                if perm != &id {
                    let old_cursor = self.get_cursor(topic, id.identifier()).unwrap();
                    self.remove(id.identifier());
                    old_cursor
                } else {
                    cursor
                }
            }
            None => cursor,
        };

        self.0
            .get_mut(topic)
            .and_then(|branch| branch.cursors.insert(id, cursor))
    }

    /// If the [`Topic`] exists, update the latest_link, otherwise insert a new [`Topic`] with the
    /// latest_link.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the branch that the cursor is stored in.
    /// * `latest_link`: The latest link that was received for this topic.
    pub(crate) fn set_latest_link(&mut self, topic: Topic, latest_link: MsgId) {
        match self.0.get_mut(&topic) {
            Some(branch) => {
                branch.latest_link = latest_link;
            }
            None => {
                let branch = InnerCursorStore {
                    latest_link,
                    ..Default::default()
                };
                self.0.insert(topic, branch);
            }
        }
    }

    /// Get the latest link for a topic, if it exists.
    ///
    /// # Arguments
    /// * `topic`: The [`Topic`] of the message.
    ///
    /// Returns:
    /// The latest link for the topic.
    pub(crate) fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.0.get(topic).map(|branch| branch.latest_link)
    }
}

/// Represents a branch, and wraps a map from a [`Permissioned`] [`Identifier`] to a cursor. Also
/// contains the latest [`MsgId`] link that was processed in the branch.
#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct InnerCursorStore {
    /// A mapping of publishers to their cursor
    cursors: HashMap<Permissioned<Identifier>, usize>,
    /// Latest message link processed in the branch
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
        id::{Ed25519, Identity, PermissionDuration, Permissioned},
        message::Topic,
    };

    #[test]
    fn branch_store_can_remove_a_cursor_from_all_branches_at_once() {
        let mut branch_store = CursorStore::new();
        let identifier = Identity::from(Ed25519::from_seed("identifier 1")).identifier().clone();
        let permission = Permissioned::ReadWrite(identifier.clone(), PermissionDuration::Perpetual);
        let topic_1 = Topic::new("topic 1".to_string());
        let topic_2 = Topic::new("topic 2".to_string());

        branch_store.new_branch(topic_1.clone());
        branch_store.new_branch(topic_2.clone());

        branch_store.insert_cursor(&topic_1, permission.clone(), 10);
        branch_store.insert_cursor(&topic_2, permission.clone(), 20);

        branch_store.remove(&identifier);

        assert!(branch_store.get_cursor(&topic_1, &identifier).is_none());
        assert!(branch_store.get_cursor(&topic_2, &identifier).is_none());
    }
}
