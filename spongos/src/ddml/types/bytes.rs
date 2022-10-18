use core::{fmt, iter::FromIterator};

use alloc::{string::String, vec::Vec};

/// Variable-size array of bytes wrapper for `DDML` operations, the size is not known at compile
/// time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bytes<T = Vec<u8>>(T);

impl<T> Bytes<T> {
    /// Wraps a variable-size array of bytes for `DDML` operations
    ///
    /// # Arguments
    /// * `bytes`: The byte array to be wrapped.
    pub fn new(bytes: T) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the inner byte array.
    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    /// Returns a mutable reference to the inner byte array.
    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Returns a new `Bytes` wrapper around a reference to the inner byte array
    pub fn as_ref(&self) -> Bytes<&T> {
        Bytes::new(self.inner())
    }

    /// Returns a new `Bytes` wrapper around a mutable reference to the inner byte array
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
    /// This is the borrowed alternative of the owned [`Bytes::to_string()`].
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(self.0.as_ref()).ok()
    }

    /// This function returns a slice of the bytes of the inner byte array.
    ///
    /// Returns:
    /// A slice of the bytes in the inner array.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns the length of the inner byte array.
    ///
    /// Returns:
    /// Length of inner array.
    pub(crate) fn len(&self) -> usize {
        self.0.as_ref().len()
    }
}

impl<T> Bytes<T>
where
    T: AsMut<[u8]>,
{
    /// This function returns a mutable slice of the internal array.
    ///
    /// Returns:
    /// A mutable slice of the underlying array.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Bytes<&mut Vec<u8>> {
    /// Resize the underlying byte array.
    pub(crate) fn resize(&mut self, new_size: usize) {
        self.0.resize(new_size, 0)
    }
}

impl Bytes<Vec<u8>> {
    /// Consumes the [`Bytes`] wrapper, returning the internal `Vec<u8>`
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Attempts to convert the Bytes into a String
    ///
    /// If the Bytes are valid UTF8, this method returns `Some(String)`, otherwise returns `None`
    /// This is the owned alternative of the borrowed [`Bytes::to_str()`].
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
