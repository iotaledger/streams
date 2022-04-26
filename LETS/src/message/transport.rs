// Rust
use alloc::vec::Vec;
use core::fmt;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{
            unwrap,
            Absorb,
        },
        modifiers::External,
    },
    PRP,
};

// Local
use crate::{
    link::Linked,
    message::{
        content::ContentUnwrap,
        hdf::HDF,
        preparsed::PreparsedMessage,
    },
};

/// Binary network Message representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TransportMessage<Body> {
    body: Body,
}

impl<Body> TransportMessage<Body> {
    pub(crate) fn new(body: Body) -> Self {
        Self { body }
    }

    fn map<B, F: FnOnce(Body) -> B>(self, f: F) -> TransportMessage<B> {
        TransportMessage { body: f(self.body) }
    }

    fn body(&self) -> &Body {
        &self.body
    }
}

impl<T> TransportMessage<T>
where
    T: AsRef<[u8]>,
{
    pub async fn parse_header<'a, F, Address>(&'a self) -> Result<PreparsedMessage<'a, F, Address>>
    where
        unwrap::Context<F, &'a [u8]>: ContentUnwrap<HDF<Address>>,
        F: PRP + Default,
        Address: Default,
    {
        let mut ctx = unwrap::Context::new(self.body().as_ref());
        let mut header = HDF::default();

        ctx.unwrap(&mut header).await?;

        Ok(PreparsedMessage::new(header, ctx))
    }
}
