use core::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uint8(pub u8);

impl Uint8 {
    pub fn to_bytes(self) -> [u8; 1] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 1]) -> Self {
        Self(u8::from_be_bytes(bytes))
    }
}

impl fmt::Display for Uint8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uint16(pub u16);

impl Uint16 {
    pub fn to_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }
}

impl fmt::Display for Uint16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uint32(pub u32);

impl Uint32 {
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

impl fmt::Display for Uint32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uint64(pub u64);

impl Uint64 {
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
