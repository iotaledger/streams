use core::fmt;

/// A single byte encoded wrapper for a `u8`
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint8(u8);

impl Uint8 {
    /// Create a new wrapper for encoding/decoding a `u8`
    ///
    /// # Arguments
    /// * `u`: `u8` to be wrapped
    pub fn new(u: u8) -> Self {
        Self(u)
    }

    /// Converts the inner `u8` into a byte array of length 1
    pub(crate) fn to_bytes(self) -> [u8; 1] {
        self.0.to_be_bytes()
    }

    /// Converts a byte array of length 1 into a [`Uint8`] wrapper
    ///
    /// # Arguments
    /// * `bytes`: a byte array of length 1
    pub(crate) fn from_bytes(bytes: [u8; 1]) -> Self {
        Self(u8::from_be_bytes(bytes))
    }

    /// Returns the inner `u8`
    pub fn inner(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for Uint8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uint8> for u8 {
    fn from(n: Uint8) -> Self {
        n.inner()
    }
}

/// A two byte encoded wrapper for a `u16`
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint16(u16);

impl Uint16 {
    /// Create a new wrapper for encoding/decoding a `u16`
    ///
    /// # Arguments
    /// * `u`: `u16` to be wrapped
    pub fn new(u: u16) -> Self {
        Self(u)
    }

    /// Converts the inner `u16` into a byte array of length 2
    pub(crate) fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Converts a byte array of length 2 into a [`Uint16`] wrapper
    ///
    /// # Arguments
    /// * `bytes`: a byte array of length 2
    pub(crate) fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Returns the inner `u16`
    pub fn inner(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Uint16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uint16> for u16 {
    fn from(n: Uint16) -> Self {
        n.inner()
    }
}

/// A four byte encoded wrapper for a `u32`
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint32(u32);

impl Uint32 {
    /// Create a new wrapper for encoding/decoding a `u32`
    ///
    /// # Arguments
    /// * `u`: `u32` to be wrapped
    pub fn new(u: u32) -> Self {
        Self(u)
    }

    /// Converts the inner `u32` into a byte array of length 4
    pub(crate) fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Converts a byte array of length 4 into a [`Uint32`] wrapper
    ///
    /// # Arguments
    /// * `bytes`: a byte array of length 4
    pub(crate) fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Returns the inner `u32`
    pub fn inner(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for Uint32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uint32> for u32 {
    fn from(n: Uint32) -> Self {
        n.inner()
    }
}

/// An eight byte encoded wrapper for a `u64`
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint64(u64);

impl Uint64 {
    /// Create a new wrapper for encoding/decoding a `u64`
    ///
    /// # Arguments
    /// * `u`: `u64` to be wrapped
    pub fn new(u: u64) -> Self {
        Self(u)
    }

    /// Converts the inner `u64` into a byte array of length 8
    pub(crate) fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Converts a byte array of length 8 into a [`Uint64`] wrapper
    ///
    /// # Arguments
    /// * `bytes`: a byte array of length 8
    pub(crate) fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// Returns the inner `u64`
    pub fn inner(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uint64> for u64 {
    fn from(n: Uint64) -> Self {
        n.inner()
    }
}
