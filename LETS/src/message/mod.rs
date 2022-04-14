/// Traits for implementing Spongos de/serialization
pub(crate) mod content;
/// Header Description Frame
mod hdf;
/// Binary version of a [`GenericMessage`]
// mod binary;
/// Payload Carrying Frame
mod pcf;
/// Abstract linked-message representation
mod transport;
/// Protocol versioning tools
mod version;

// TODO: REMOVE
// mod prepared;
// mod unwrapped;
// mod wrapped;

/// Linked Message with header already parsed
mod preparsed;


// TODO: REVIEW LATER
// use hdf::HDF;
// use pcf::PCF;

// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::commands::{
        sizeof,
        wrap,
    },
    Spongos,
    PRP,
};

// Local
use content::{
    ContentSizeof,
    ContentWrap,
};
use hdf::HDF;
use pcf::PCF;
use transport::TransportMessage;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub(crate) struct Message<Address, Content> {
    hdf: HDF<Address>,
    pcf: PCF<Content>,
}

impl<Address, Content> Message<Address, Content> {
    pub(crate) fn new(hdf: HDF<Address>, pcf: PCF<Content>) -> Self {
        Self { hdf, pcf }
    }

    pub(crate) fn with_header(&mut self, header: HDF<Address>) -> &mut Self {
        self.hdf = header;
        self
    }

    pub(crate) fn with_content(&mut self, content: Content) -> &mut Self {
        self.pcf.change_content(content);
        self
    }

    async fn wrap<'a, F>(&'a self) -> Result<(TransportMessage<Address, Vec<u8>>, Spongos<F>)>
    where
        F: PRP,
        Address: Clone,
            HDF<Address>: for <'b> ContentWrap<'a, F, &'b mut [u8]>,
            PCF<Content>: for <'b> ContentWrap<'a, F, &'b mut [u8]>,
    {
        let mut ctx = sizeof::Context::new();
        self.hdf.sizeof(&mut ctx).await?;
        self.pcf.sizeof(&mut ctx).await?;
        let buf_size = ctx.size();

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        self.hdf.wrap(&mut ctx).await?;
        self.pcf.wrap(&mut ctx).await?;
        // If buffer is not empty, it's an implementation error, panic
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap {}",
            ctx.stream().len()
        );
        let spongos = ctx.finalize();

        Ok((TransportMessage::new(self.hdf.address().clone(), buf), spongos))
    }
}
