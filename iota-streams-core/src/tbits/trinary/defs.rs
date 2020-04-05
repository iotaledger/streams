use std::fmt;
use std::hash;

/// Unsigned trit type with values in range 0..2. Used by Troika implementation.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trit(pub u8); //0..2
pub const MAX_TRIT: Trit = Trit(2);
pub const MIN_TRIT: Trit = Trit(0);

impl fmt::Display for Trit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl hash::Hash for Trit {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Unsigned tryte type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Tryte(pub u8); //0..26
pub const MAX_TRYTE: Tryte = Tryte(26);
pub const MIN_TRYTE: Tryte = Tryte(0);

impl fmt::Display for Tryte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed trit type: -1..1.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trint1(pub i8);
pub const MAX_TRINT1: Trint1 = Trint1(1);
pub const MIN_TRINT1: Trint1 = Trint1(-1);

impl fmt::Display for Trint1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed tryte type: -13..13.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trint3(pub i8);
pub const MAX_TRINT3: Trint3 = Trint3(13);
pub const MIN_TRINT3: Trint3 = Trint3(-13);

impl fmt::Display for Trint3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed 6-trit integer type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trint6(pub i16);
pub const MAX_TRINT6: Trint6 = Trint6(364);
pub const MIN_TRINT6: Trint6 = Trint6(-364);

impl fmt::Display for Trint6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed 9-trit integer type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trint9(pub i16);
pub const MAX_TRINT9: Trint9 = Trint9(9841);
pub const MIN_TRINT9: Trint9 = Trint9(-9841);

impl fmt::Display for Trint9 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed 18-trit integer type.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Trint18(pub i32);
pub const MAX_TRINT18: Trint18 = Trint18(193_710_244);
pub const MIN_TRINT18: Trint18 = Trint18(-193_710_244);

impl fmt::Display for Trint18 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
