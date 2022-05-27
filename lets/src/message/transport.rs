// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{ddml::commands::unwrap, PRP};

// Local
use crate::message::{content::ContentUnwrap, hdf::HDF, preparsed::PreparsedMessage};

/// Binary network Message representation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TransportMessage(Vec<u8>);

impl TransportMessage {
    pub(crate) fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    pub(crate) fn body(&self) -> &Vec<u8> {
        &self.0
    }

    pub(crate) fn into_body(self) -> Vec<u8> {
        self.0
    }
}

impl TransportMessage {
    pub async fn parse_header<F>(self) -> Result<PreparsedMessage<F>>
    where
        F: PRP + Default + Send,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        let mut header = HDF::default();

        ctx.unwrap(&mut header).await?;

        let (spongos, cursor) = ctx.finalize();

        Ok(PreparsedMessage::new(self, header, spongos, cursor))
    }
}

impl From<TransportMessage> for Vec<u8> {
    fn from(message: TransportMessage) -> Self {
        message.into_body()
    }
}

impl AsRef<[u8]> for TransportMessage {
    fn as_ref(&self) -> &[u8] {
        self.body().as_ref()
    }
}
