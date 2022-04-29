/// Traits for implementing Spongos de/serialization
mod content;
/// Header Description Frame
mod hdf;
/// Payload Carrying Frame
mod pcf;
/// Abstract linked-message representation
mod transport;
/// Protocol versioning tools
mod version;

/// Linked Message with header already parsed
mod preparsed;

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
        Commit,
    },
    Spongos,
    PRP,
};

// Local
pub use content::{
    ContentDecrypt,
    ContentEncrypt,
    ContentEncryptSizeOf,
    ContentSign,
    ContentSignSizeof,
    ContentSizeof,
    ContentUnwrap,
    ContentVerify,
    ContentWrap,
};
pub use hdf::HDF;
pub use pcf::PCF;
pub use preparsed::PreparsedMessage;
pub use transport::TransportMessage;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Message<Address, Payload> {
    header: HDF<Address>,
    payload: PCF<Payload>,
}

impl<Address, Payload> Message<Address, Payload> {
    pub fn new(header: HDF<Address>, payload: PCF<Payload>) -> Self {
        Self { header, payload }
    }

    pub(crate) fn with_header(&mut self, header: HDF<Address>) -> &mut Self {
        self.header = header;
        self
    }

    pub fn with_content(&mut self, content: Payload) -> &mut Self {
        self.payload.change_content(content);
        self
    }

    pub fn header(&self) -> &HDF<Address> {
        &self.header
    }

    pub fn take_header(&mut self) -> HDF<Address>
    where
        Address: Default,
    {
        core::mem::take(&mut self.header)
    }

    pub fn payload(&self) -> &PCF<Payload> {
        &self.payload
    }

    pub fn into_payload(self) -> PCF<Payload> {
        self.payload
    }

    pub async fn wrap<F>(&mut self) -> Result<(TransportMessage<Vec<u8>>, Spongos<F>)>
    where
        F: PRP + Default,
        for<'b> wrap::Context<F, &'b mut [u8]>: ContentWrap<HDF<Address>> + ContentWrap<PCF<Payload>>,
        sizeof::Context: ContentSizeof<HDF<Address>> + ContentSizeof<PCF<Payload>>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.header).await?.commit()?.sizeof(&self.payload).await?;
        let buf_size = ctx.size();

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        ctx.wrap(&mut self.header)
            .await?
            .commit()?
            .wrap(&mut self.payload)
            .await?;
        // If buffer is not empty, it's an implementation error, panic
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap {}",
            ctx.stream().len()
        );
        let spongos = ctx.finalize();

        Ok((TransportMessage::new(buf), spongos))
    }
}
