// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::commands::unwrap,
    PRP,
};

// Local
use crate::message::{
    content::ContentUnwrap,
    hdf::HDF,
    preparsed::PreparsedMessage,
};

/// Binary network Message representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TransportMessage<Body> {
    body: Body,
}

impl<Body> TransportMessage<Body> {
    pub(crate) fn new(body: Body) -> Self {
        Self { body }
    }

    pub(crate) fn body(&self) -> &Body {
        &self.body
    }
}

impl<T> TransportMessage<T>
where
    T: AsRef<[u8]>,
{
    pub async fn parse_header<F, Address>(self) -> Result<PreparsedMessage<T, F, Address>>
    where
        for<'a> unwrap::Context<F, &'a [u8]>: ContentUnwrap<HDF<Address>>,
        F: PRP + Default,
        Address: Default,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        let mut header = HDF::default();

        ctx.unwrap(&mut header).await?;

        let (spongos, cursor) = ctx.finalize();

        Ok(PreparsedMessage::new(self, header, spongos, cursor))
    }
}

impl From<TransportMessage<Vec<u8>>> for Vec<u8> {
    fn from(message: TransportMessage<Vec<u8>>) -> Self {
        message.body
    }
}
