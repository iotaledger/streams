use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt::Formatter,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::{Bytes, NBytes},
    },
    error::Result as SpongosResult,
    KeccakF1600, Spongos, PRP,
};

use crate::error::Result;

/// A wrapper around a `String` used for identifying a branch within a `Stream`
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash, serde::Serialize)]
pub struct Topic(String);

impl Topic {
    /// Create a new [`Topic`] wrapper for the provided `String`
    ///
    /// # Arguments
    /// * `t`: A unique branch identifier
    pub fn new(t: String) -> Self {
        Self(t)
    }

    /// Returns a reference to the inner branch identifier `String`
    pub fn str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Topic {
    fn from(t: &str) -> Self {
        Self(t.to_string())
    }
}

impl From<String> for Topic {
    fn from(t: String) -> Self {
        Self(t)
    }
}

impl TryFrom<&[u8]> for Topic {
    type Error = crate::error::Error;
    fn try_from(t: &[u8]) -> Result<Self> {
        let topic = String::from_utf8(t.to_vec())?;
        Ok(Topic(topic))
    }
}

impl TryFrom<Vec<u8>> for Topic {
    type Error = crate::error::Error;
    fn try_from(t: Vec<u8>) -> Result<Self> {
        let topic = String::from_utf8(t)?;
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

impl From<Topic> for Cow<'_, Topic> {
    fn from(topic: Topic) -> Self {
        Self::Owned(topic)
    }
}

impl<'a> From<&'a Topic> for Cow<'a, Topic> {
    fn from(topic: &'a Topic) -> Self {
        Self::Borrowed(topic)
    }
}

impl Mask<&Topic> for sizeof::Context {
    fn mask(&mut self, topic: &Topic) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(topic))
    }
}

impl<OS, F> Mask<&Topic> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, topic: &Topic) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(topic))
    }
}

impl<IS, F> Mask<&mut Topic> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, topic: &mut Topic) -> SpongosResult<&mut Self> {
        let mut topic_bytes = topic.as_ref().to_vec();
        self.mask(Bytes::new(&mut topic_bytes))?;
        *topic = topic_bytes
            .try_into()
            .map_err(|e: crate::error::Error| spongos::error::Error::Context("Mask", e.to_string()))?;
        Ok(self)
    }
}

/// A 16 byte fixed size hash representation of a [`Topic`]
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Debug, Default, Hash, serde::Serialize)]
pub struct TopicHash([u8; 16]);

impl From<&Topic> for TopicHash {
    fn from(topic: &Topic) -> Self {
        let topic_hash: [u8; 16] = Spongos::<KeccakF1600>::init().sponge(topic.as_ref());
        Self(topic_hash)
    }
}

impl From<&str> for TopicHash {
    fn from(t: &str) -> Self {
        TopicHash::from(&Topic::from(t))
    }
}

impl core::fmt::Display for TopicHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl AsRef<[u8]> for TopicHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Mask<&TopicHash> for sizeof::Context {
    fn mask(&mut self, topic_hash: &TopicHash) -> SpongosResult<&mut Self> {
        self.mask(NBytes::<[u8; 16]>::new(topic_hash.0))
    }
}

impl<OS, F> Mask<&TopicHash> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, topic_hash: &TopicHash) -> SpongosResult<&mut Self> {
        self.mask(NBytes::<[u8; 16]>::new(topic_hash.0))
    }
}

impl<IS, F> Mask<&mut TopicHash> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, topic_hash: &mut TopicHash) -> SpongosResult<&mut Self> {
        self.mask(NBytes::<&mut [u8; 16]>::new(&mut topic_hash.0))?;
        Ok(self)
    }
}
