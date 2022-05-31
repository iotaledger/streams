use core::{fmt, iter::FromIterator};

use alloc::{string::String, vec::Vec};
use anyhow::anyhow;

/// Variable-size array of bytes, the size is not known at compile time and is encoded in trinary
/// representation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bytes<T = Vec<u8>>(T);

impl<T> Bytes<T> {
    pub fn new(bytes: T) -> Self {
        Self(bytes)
    }

    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }

    pub fn as_ref(&self) -> Bytes<&T> {
        Bytes::new(self.inner())
    }

    pub fn as_mut(&mut self) -> Bytes<&mut T> {
        Bytes::new(self.inner_mut())
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
        core::str::from_utf8(self.0.as_ref()).ok()
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
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Bytes<&mut Vec<u8>> {
    // Return an error if size exceeds u32 max size to avoid panic
    // TODO: Remove anyhow error and replace with no_std compatible error handling
    pub(crate) fn resize(&mut self, new_size: usize) -> anyhow::Result<()> {
        if new_size > u32::MAX as usize {
            return Err(anyhow!("{} exceeds maximum available space for Byte resize", new_size));
        }
        self.0.resize(new_size, 0);
        Ok(())
    }
}

impl Bytes<Vec<u8>> {
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Attempts to convert the Bytes into a String
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(String)`, otherwise returns `None`
    /// This is the owned alternative of the borrowed [`Bytes::as_str()`].
    pub fn to_string(self) -> Option<String> {
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

impl<T, A> FromIterator<A> for Bytes<T>
where
    T: FromIterator<A>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = A>,
    {
        Bytes::new(iter.into_iter().collect())
    }
}
