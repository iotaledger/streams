use core::fmt::{Debug, Display, Formatter, Result};

/// Represents an input state for message identifier generation.
/// Contains an Address and sequencing states.
#[derive(Clone, Copy, Hash, Default, PartialEq, Eq)]
struct Cursor<Link> {
    link: Link,
    branch_no: u32,
    seq_no: u32,
}

impl<Link> Cursor<Link> {
    fn new(link: Link) -> Self {
        Self {
            link,
            branch_no: 0,
            seq_no: 0,
        }
    }
    fn new_at(link: Link, branch_no: u32, seq_no: u32) -> Self {
        Self {
            link,
            branch_no,
            seq_no,
        }
    }

    fn next_branch(&mut self) {
        self.branch_no += 1;
        self.seq_no = 0;
    }

    fn next_seq(&mut self) {
        self.seq_no += 1;
    }

    fn seq_num(&self) -> u64 {
        (self.branch_no as u64) << 32 | (self.seq_no as u64)
    }

    fn set_seq_num(&mut self, seq_num: u64) {
        self.seq_no = seq_num as u32;
        self.branch_no = (seq_num >> 32) as u32;
    }

    fn as_ref(&self) -> Cursor<&Link> {
        Cursor {
            link: &self.link,
            branch_no: self.branch_no,
            seq_no: self.seq_no,
        }
    }

    fn as_mut(&mut self) -> Cursor<&mut Link> {
        Cursor {
            link: &mut self.link,
            branch_no: self.branch_no,
            seq_no: self.seq_no,
        }
    }
}

impl<Link: Display> Display for Cursor<Link> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "<{},{}:{}>", self.link, self.branch_no, self.seq_no)
    }
}

impl<Link: Debug> Debug for Cursor<Link> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "<{:?},{}:{}>", self.link, self.branch_no, self.seq_no)
    }
}