use alloc::{string::String, vec::Vec};
use anyhow::{anyhow, ensure, Error};
use core::{
    convert::{TryFrom, TryInto},
    fmt::Formatter,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::NBytes,
    },
    PRP,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Topic(pub [u8; 32]);

impl Topic {
    pub fn new(t: &[u8]) -> Result<Self, Error> {
        t.try_into()
    }
}

impl TryFrom<&[u8]> for Topic {
    type Error = anyhow::Error;
    fn try_from(t: &[u8]) -> Result<Self, Self::Error> {
        ensure!(
            t.len() <= 32,
            anyhow!("Topic cannot exceed 32 bytes in length: {}", t.len())
        );
        let mut topic = [0u8; 32];
        topic[..t.len()].copy_from_slice(t);
        Ok(Topic(topic))
    }
}

impl core::fmt::Display for Topic {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl AsRef<[u8]> for Topic {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Topic {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Mask<&Topic> for sizeof::Context {
    fn mask(&mut self, topic: &Topic) -> anyhow::Result<&mut Self> {
        self.mask(NBytes::new(topic))
    }
}

impl<OS, F> Mask<&Topic> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, topic: &Topic) -> anyhow::Result<&mut Self> {
        self.mask(NBytes::new(topic))
    }
}

impl<IS, F> Mask<&mut Topic> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, topic: &mut Topic) -> anyhow::Result<&mut Self> {
        self.mask(NBytes::new(topic))
    }
}
