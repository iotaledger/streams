use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{convert::TryFrom, fmt::Formatter};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Bytes,
    },
    PRP,
};

#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
pub struct Topic(String);

impl Topic {
    pub fn new(t: String) -> Self {
        Self(t)
    }
}

impl From<&str> for Topic {
    fn from(t: &str) -> Self {
        Self(t.to_string())
    }
}

impl TryFrom<&[u8]> for Topic {
    type Error = anyhow::Error;
    fn try_from(t: &[u8]) -> Result<Self, Self::Error> {
        let topic = String::from_utf8(t.to_vec())?;
        Ok(Topic(topic))
    }
}

impl core::fmt::Display for Topic {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl AsRef<[u8]> for Topic {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<Vec<u8>> for Topic {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        unsafe { self.0.as_mut_vec() }
    }
}

impl Mask<&Topic> for sizeof::Context {
    fn mask(&mut self, topic: &Topic) -> anyhow::Result<&mut Self> {
        self.mask(Bytes::new(topic))
    }
}

impl<OS, F> Mask<&Topic> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, topic: &Topic) -> anyhow::Result<&mut Self> {
        self.mask(Bytes::new(topic))
    }
}

impl<IS, F> Mask<&mut Topic> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, topic: &mut Topic) -> anyhow::Result<&mut Self> {
        self.mask(Bytes::new(topic.as_mut()))?;
        Ok(self)
    }
}
