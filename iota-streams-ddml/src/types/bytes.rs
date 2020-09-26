use core::{
    fmt,
    hash,
};

use iota_streams_core::prelude::Vec;

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl hash::Hash for Bytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}
