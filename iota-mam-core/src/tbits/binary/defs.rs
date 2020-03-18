use std::fmt;
use std::hash;
use std::iter;

/// Bit type with values in range 0..1.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Bit(pub u8); //0..1
pub const MAX_BIT: Bit = Bit(1);
pub const MIN_BIT: Bit = Bit(0);

impl fmt::Display for Bit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl hash::Hash for Bit {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Unsigned byte type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Byte(pub u8); //0..255
pub const MAX_BYTE: Byte = Byte(255);
pub const MIN_BYTE: Byte = Byte(0);

impl fmt::Display for Byte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl iter::Step for Byte {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        if start.0 <= end.0 {
            Some((end.0 - start.0) as usize)
        } else {
            None
        }
    }

    fn replace_one(&mut self) -> Self {
        let this = *self;
        *self = Self(1);
        this
    }
    fn replace_zero(&mut self) -> Self {
        let this = *self;
        *self = Self(0);
        this
    }

    fn add_one(&self) -> Self {
        debug_assert!(*self < MAX_BYTE);
        Self(self.0 + 1)
    }
    fn sub_one(&self) -> Self {
        debug_assert!(*self > MIN_BYTE);
        Self(self.0 - 1)
    }

    fn add_usize(&self, n: usize) -> Option<Self> {
        if n < 27 && self.0 + n as u8 <= MAX_BYTE.0 {
            Some(Self(self.0 + n as u8))
        } else {
            None
        }
    }
    fn sub_usize(&self, n: usize) -> Option<Self> {
        if self.0 as usize >= n {
            Some(Self(self.0 - n as u8))
        } else {
            None
        }
    }
}
