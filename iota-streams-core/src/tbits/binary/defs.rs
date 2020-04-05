use std::fmt;
use std::hash;

/// Bit type with values in range 0..1.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Bit(pub u8); //0..1
pub const MAX_BIT: Bit = Bit(1);
pub const MIN_BIT: Bit = Bit(0);

impl fmt::Display for Bit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_assert_eq!(0, self.0 & 0xfe_u8);
        write!(f, "{:?}", self.0)
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
        write!(f, "{:02x}", self.0)
    }
}
