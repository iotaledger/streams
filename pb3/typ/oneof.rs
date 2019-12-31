//! This module describes PB3 `oneof` modifier.

use crate::trits;
use super::trint::{sizeof_tryte, Trint3, Tryte};

/// `oneof` is encoded just like `tryte.
pub type OneOf = Tryte;

/// Constructor for `oneof`.
pub fn oneof(n: trits::Trint3) -> OneOf {
    Trint3(n)
}

pub fn sizeof_oneof() -> usize { sizeof_tryte() }

