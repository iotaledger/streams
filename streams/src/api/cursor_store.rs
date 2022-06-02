// Rust
use core::fmt;

// 3rd-party
use hashbrown::HashMap;

// IOTA

// Streams
use lets::id::Identifier;

// Local

#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct CursorStore(HashMap<Identifier, usize>);

impl CursorStore {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn is_cursor_tracked(&self, id: &Identifier) -> bool {
        self.0.contains_key(id)
    }

    pub(crate) fn get_cursor(&self, id: &Identifier) -> Option<usize> {
        self.0.get(id).copied()
    }

    pub(crate) fn insert_cursor(&mut self, id: Identifier, cursor: usize) -> bool {
        self.0.insert(id, cursor).is_none()
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, usize)> + ExactSizeIterator + Clone + '_ {
        self.0.iter().map(|(identifier, cursor)| (*identifier, *cursor))
    }

    pub(crate) fn remove(&mut self, id: &Identifier) -> bool {
        self.0.remove(id).is_some()
    }
}

impl fmt::Debug for CursorStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "* cursors:")?;
        for (id, cursor) in self.cursors() {
            writeln!(f, "\t{:?} => {}", id, cursor)?;
        }
        Ok(())
    }
}
