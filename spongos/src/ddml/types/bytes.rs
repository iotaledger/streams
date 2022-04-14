use core::{
    fmt,
    hash,
};

use alloc::vec::Vec;
use alloc::string::String;


/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Attempts to convert the Bytes into a str
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(str)`, otherwise returns `None`
    /// This is the borrowed alternative of the owned [`Bytes::into_string()`].
    fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Attempts to convert the Bytes into a String
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(String)`, otherwise returns `None`
    /// This is the owned alternative of the borrowed [`Bytes::as_str()`].
    fn into_string(self) -> Option<String> {
        String::from_utf8(self.0).ok()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn resize(&mut self, new_size: usize) {
        self.0.resize(new_size, 0)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

// TODO: REMOVE
// impl<'a> From<&'a Vec<u8>> for &'a Bytes {
//     fn from(v: &Vec<u8>) -> &Bytes {
//         unsafe { &*(v as *const Vec<u8> as *const Bytes) }
//     }
// }

// impl<'a> From<&'a mut Vec<u8>> for &'a mut Bytes {
//     fn from(v: &mut Vec<u8>) -> &mut Bytes {
//         unsafe { &mut *(v as *mut Vec<u8> as *mut Bytes) }
//     }
// }

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(b: Bytes) -> Self {
        b.0
    }
}

// TODO: REMOVE
// impl From<&[u8]> for Bytes {
//     fn from(s: &[u8]) -> Self {
//         Self(s.to_vec())
//     }
// }

// /// Use `b"<content>".into()` as a convenient way to create new `Bytes`
// #[rustversion::since(1.51)]
// impl<const N: usize> From<[u8; N]> for Bytes {
//     fn from(v: [u8; N]) -> Self {
//         Self(v.to_vec())
//     }
// }

// /// Use `b"<content>".into()` as a convenient way to create new `Bytes`
// #[rustversion::since(1.51)]
// impl<const N: usize> From<&[u8; N]> for Bytes {
//     fn from(v: &[u8; N]) -> Self {
//         Self(v.to_vec())
//     }
// }

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}
