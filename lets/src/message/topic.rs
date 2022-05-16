use core::convert::{TryFrom, TryInto};
use alloc::{
    vec::Vec,
    string::String,
};
use core::fmt::Formatter;
use anyhow::{anyhow, ensure, Error};


#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Topic(pub [u8;32]);

impl Topic {
    pub fn new(t: &[u8]) -> Result<Self, Error> {
        t.try_into()
    }

    pub fn inner(&self) -> &[u8] {
        &self.0
    }

    pub fn to_inner(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for Topic {
    type Error = anyhow::Error;
    fn try_from(topic: Vec<u8>) -> Result<Self, Self::Error> {
        topic.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for Topic {
    type Error = anyhow::Error;
    fn try_from(t: &[u8]) -> Result<Self, Self::Error> {
        ensure!(t.len() <= 32, anyhow!("Topic cannot exceed 32 bytes in length: {}", t.len()));
        let mut topic = [0u8;32];
        topic[..t.len()].copy_from_slice(&t);
        Ok(Topic(topic))
    }
}

impl From<[u8;32]> for Topic {
    fn from(t: [u8; 32]) -> Self {
        Self(t)
    }
}

impl core::fmt::Display for Topic {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl AsRef<[u8]> for Topic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
