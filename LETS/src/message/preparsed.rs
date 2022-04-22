// Rust
use core::fmt;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::commands::unwrap,
    Spongos,
    PRP,
};

// local
use crate::message::{
    content::ContentUnwrap,
    hdf::HDF,
    pcf::PCF,
    Message,
};

/// Message context preparsed for unwrapping.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct PreparsedMessage<'a, F, Address> {
    hdf: HDF<Address>,
    ctx: unwrap::Context<F, &'a [u8]>,
}

impl<'a, F, Address> PreparsedMessage<'a, F, Address> {
    pub(crate) fn new(hdf: HDF<Address>, ctx: unwrap::Context<F, &'a [u8]>) -> Self {
        Self { hdf, ctx }
    }

    fn is_content_type(&self, content_type: u8) -> bool {
        self.header().content_type() == content_type
    }

    fn header(&self) -> &HDF<Address> {
        &self.hdf
    }

    async fn unwrap<Content>(mut self, content: Content) -> Result<(Message<Address, Content>, Spongos<F>)>
    where
        unwrap::Context<F, &'a [u8]>: ContentUnwrap<PCF<Content>>,
        F: PRP,
    {
        let mut pcf = PCF::<()>::default().with_content(content);
        self.ctx.unwrap(&mut pcf).await?;
        // Commit Spongos and discard `self.ctx.stream` that should be empty
        let spongos = self.ctx.finalize();
        Ok((Message::new(self.hdf, pcf), spongos))
    }
}

impl<'a, F, Link> fmt::Debug for PreparsedMessage<'a, F, Link>
where
    Link: fmt::Debug + Default + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{header: {:?}, ctx: {:?}}}", self.hdf, &self.ctx.stream()[..10])
    }
}
