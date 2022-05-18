// Rust

// 3rd-party
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::commands::{sizeof, wrap, Commit},
    Spongos, PRP,
};

// Local
use super::{
    content::{ContentSizeof, ContentWrap},
    hdf::HDF,
    pcf::PCF,
    transport::TransportMessage,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Message<Content> {
    header: HDF,
    payload: PCF<Content>,
}

impl<Payload> Message<Payload> {
    pub fn new(header: HDF, payload: PCF<Payload>) -> Self {
        Self { header, payload }
    }

    pub fn with_header(&mut self, header: HDF) -> &mut Self {
        self.header = header;
        self
    }

    pub fn with_content(&mut self, content: Payload) -> &mut Self {
        self.payload.change_content(content);
        self
    }

    pub fn header(&self) -> HDF {
        self.header
    }

    pub fn payload(&self) -> &PCF<Payload> {
        &self.payload
    }

    pub fn into_payload(self) -> PCF<Payload> {
        self.payload
    }

    pub async fn wrap<F>(&mut self) -> Result<(TransportMessage, Spongos<F>)>
    where
        F: PRP + Default,
        for<'b> wrap::Context<&'b mut [u8], F>: ContentWrap<HDF> + ContentWrap<PCF<Payload>>,
        sizeof::Context: ContentSizeof<HDF> + ContentSizeof<PCF<Payload>>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.header).await?.commit()?.sizeof(&self.payload).await?;
        let buf_size = ctx.finalize();

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
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );
        let spongos = ctx.finalize();

        Ok((TransportMessage::new(buf), spongos))
    }
}
