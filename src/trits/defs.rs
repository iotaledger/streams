/// Unsigned trit type with values in range 0..2. Used by Troika implementation.
pub type Trit = u8; //0..2
/// Unsigned tryte type.
pub type Tryte = u8; //0..26

/// Signed trit type: -1..1.
pub type Trint1 = i8;
pub const MAX_TRINT1: Trint1 = 1;
pub const MIN_TRINT1: Trint1 = -MAX_TRINT1;

/// Signed tryte type: -13..13.
pub type Trint3 = i8;
pub const MAX_TRINT3: Trint3 = 13;
pub const MIN_TRINT3: Trint3 = -MAX_TRINT3;

/// Signed 6-trit integer type.
pub type Trint6 = i16;
pub const MAX_TRINT6: Trint6 = 364;
pub const MIN_TRINT6: Trint6 = -MAX_TRINT6;

/// Signed 9-trit integer type.
pub type Trint9 = i16;
pub const MAX_TRINT9: Trint9 = 9841;
pub const MIN_TRINT9: Trint9 = -MAX_TRINT9;

/// Signed 18-trit integer type.
pub type Trint18 = i32;
pub const MAX_TRINT18: Trint18 = 193_710_244;
pub const MIN_TRINT18: Trint18 = -MAX_TRINT18;
