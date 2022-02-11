use core::{
    fmt,
    hash,
};

use iota_streams_core::{
    prelude::{
        hex,
        String,
        Vec,
    },
    rustversion,
};

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
#[derive(Eq, Clone, Debug, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Attempts to convert the Bytes into a str
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(str)`, otherwise returns `None`
    /// This is the borrowed alternative of the owned [`Bytes::into_string()`].
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Attempts to convert the Bytes into a String
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(String)`, otherwise returns `None`
    /// This is the owned alternative of the borrowed [`Bytes::as_str()`].
    pub fn into_string(self) -> Option<String> {
        String::from_utf8(self.0).ok()
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl hash::Hash for Bytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

impl<'a> From<&'a Vec<u8>> for &'a Bytes {
    fn from(v: &Vec<u8>) -> &Bytes {
        unsafe { &*(v as *const Vec<u8> as *const Bytes) }
    }
}

impl<'a> From<&'a mut Vec<u8>> for &'a mut Bytes {
    fn from(v: &mut Vec<u8>) -> &mut Bytes {
        unsafe { &mut *(v as *mut Vec<u8> as *mut Bytes) }
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(b: Bytes) -> Self {
        b.0
    }
}

impl From<&[u8]> for Bytes {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

/// Use `b"<content>".into()` as a convenient way to create new `Bytes`
#[rustversion::since(1.51)]
impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(v: [u8; N]) -> Self {
        Self(v.to_vec())
    }
}

/// Use `b"<content>".into()` as a convenient way to create new `Bytes`
#[rustversion::since(1.51)]
impl<const N: usize> From<&[u8; N]> for Bytes {
    fn from(v: &[u8; N]) -> Self {
        Self(v.to_vec())
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
