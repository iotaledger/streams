// Rust
use alloc::borrow::Cow;
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA

// Streams
use lets::{address::MsgId, id::Identifier, message::Topic};

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

    pub(crate) fn is_cursor_tracked(&self, topic: &Topic, id: &Identifier) -> bool {
        self.0
            .get(topic)
            .map_or(false, |branch| branch.cursors.contains_key(id))
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        let removals = self.0.values_mut().flat_map(|branch| branch.cursors.remove(id));
        removals.count() > 0
    }

    pub(crate) fn get_cursor(&self, topic: &Topic, id: &Identifier) -> Option<usize> {
        self.0.get(topic).and_then(|branch| branch.cursors.get(id).copied())
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (&Topic, &Identifier, usize)> + Clone + '_ {
        self.0
            .iter()
            .flat_map(|(topic, branch)| branch.cursors.iter().map(move |(id, cursor)| (topic, id, *cursor)))
    }

    pub(crate) fn insert_cursor(&mut self, topic: &Topic, id: Identifier, cursor: usize) -> Option<usize> {
        if let Some(branch) = self.0.get_mut(topic) {
            return branch.cursors.insert(id, cursor);
        }
        None
    }

    pub(crate) fn set_anchor<'a, T>(&mut self, topic: T, anchor: MsgId) -> Option<InnerCursorStore>
    where
        T: Into<Cow<'a, Topic>>,
    {
        let topic = topic.into();
        match self.0.get_mut(&topic) {
            Some(branch) => {
                branch.anchor = anchor;
                None
            }
            None => {
                let branch = InnerCursorStore {
                    anchor,
                    ..Default::default()
                };
                self.0.insert(topic.into_owned(), branch)
            }
        }
    }

    pub(crate) fn set_latest_link<'a, T>(&mut self, topic: T, latest_link: MsgId) -> Option<InnerCursorStore>
    where
        T: Into<Cow<'a, Topic>>,
    {
        let topic = topic.into();
        match self.0.get_mut(&topic) {
            Some(branch) => {
                branch.latest_link = latest_link;
                None
            }
            None => {
                let branch = InnerCursorStore {
                    latest_link,
                    ..Default::default()
                };
                self.0.insert(topic.into_owned(), branch)
            }
        }
    }

    pub(crate) fn get_anchor(&self, topic: &Topic) -> Option<MsgId> {
        self.0.get(topic).map(|branch| branch.anchor)
    }

    pub(crate) fn get_latest_link(&self, topic: &Topic) -> Option<MsgId> {
        self.0.get(topic).map(|branch| branch.latest_link)
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct InnerCursorStore {
    cursors: HashMap<Identifier, usize>,
    anchor: MsgId,
    latest_link: MsgId,
}

impl fmt::Debug for InnerCursorStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\t* anchor: {}", self.anchor)?;
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
