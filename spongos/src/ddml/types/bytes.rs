use core::{
    fmt,
    hash,
};

use alloc::{
    string::String,
    vec::Vec,
};

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary representation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bytes<T>(T);
// #[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
// pub struct Bytes(Vec<u8>);

impl<T> Bytes<T> {
    pub fn new(bytes: T) -> Self {
        Self(bytes)
    }

    fn inner(&self) -> &T {
        &self.0
    }
    
    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Bytes<T>
where
    T: AsRef<[u8]>,
{
    /// Attempts to convert the Bytes into a str
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(str)`, otherwise returns `None`
    /// This is the borrowed alternative of the owned [`Bytes::into_string()`].
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0.as_ref()).ok()
    }

    fn to_vec(self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.as_ref().len()
    }
}

impl<T> Bytes<T>
where
    T: AsMut<[u8]>,
{
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Bytes<&mut Vec<u8>> {
    pub(crate) fn resize(&mut self, new_size: usize) {
        self.0.resize(new_size, 0)
    }
}

impl Bytes<Vec<u8>> {
    fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Attempts to convert the Bytes into a String
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(String)`, otherwise returns `None`
    /// This is the owned alternative of the borrowed [`Bytes::as_str()`].
    fn to_string(self) -> Option<String> {
        String::from_utf8(self.0).ok()
    }
}

impl<T> fmt::Display for Bytes<T>
where
    T: AsRef<[u8]>,
{
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

impl<T> From<T> for Bytes<T> {
    fn from(v: T) -> Self {
        Self::new(v)
    }
}

impl<'a> From<Bytes<&'a [u8]>> for &'a [u8] {
    fn from(b: Bytes<&'a [u8]>) -> Self {
        b.0
    }
}

impl From<Bytes<Vec<u8>>> for Vec<u8> {
    fn from(b: Bytes<Vec<u8>>) -> Self {
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

impl<T> AsRef<[u8]> for Bytes<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> AsMut<[u8]> for Bytes<T>
where
    T: AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
