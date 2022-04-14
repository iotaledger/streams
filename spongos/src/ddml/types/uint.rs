use core::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint8(u8);

impl Uint8 {
    pub fn new(u: u8) -> Self {
        Self(u)
    }

    pub(crate) fn to_bytes(self) -> [u8; 1] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; 1]) -> Self {
        Self(u8::from_be_bytes(bytes))
    }

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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub(crate) struct Uint16(u16);

impl Uint16 {
    pub fn new(u: u16) -> Self {
        Self(u)
    }

    pub(crate) fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub(crate) struct Uint32(u32);

impl Uint32 {
    pub fn new(u: u32) -> Self {
        Self(u)
    }

    pub(crate) fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Uint64(u64);

impl Uint64 {
    pub fn new(u: u64) -> Self {
        Self(u)
    }

    pub(crate) fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

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
