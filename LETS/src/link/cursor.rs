use core::fmt::{
    Debug,
    Display,
    Formatter,
    Result,
};

/// Represents an input state for message identifier generation.
/// Contains an Address and sequencing states.
#[derive(Clone, Copy, Hash, Default, PartialEq, Eq)]
pub struct Cursor<Address> {
    address: Address,
    seq: u64,
}

impl<Address> Cursor<Address> {
    pub fn new(address: Address, seq: u64) -> Self {
        Self { address, seq }
    }

    fn address(&self) -> &Address {
        &self.address
    }

    pub fn sequence(&self) -> u64 {
        self.seq
    }

    fn next(self, address: Address) -> Self {
        Self {
            address,
            seq: self.seq + 1,
        }
    }

    fn as_ref(&self) -> Cursor<&Address> {
        Cursor {
            address: &self.address,
            seq: self.seq,
        }
    }

    fn as_mut(&mut self) -> Cursor<&mut Address> {
        Cursor {
            address: &mut self.address,
            seq: self.seq,
        }
    }
}

impl<Link: Display> Display for Cursor<Link> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "<{} -- {}>", self.address, self.seq)
    }
}

impl<Link: Debug> Debug for Cursor<Link> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "<{:?} -- {}>", self.address, self.seq)
    }
}
