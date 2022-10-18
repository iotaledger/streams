// Rust

// IOTA

// Streams
use spongos::{
    ddml::commands::{sizeof, wrap, Commit},
    Spongos, PRP,
};

// Local
use crate::{
    error::Result,
    message::{
        content::{ContentSizeof, ContentWrap},
        hdf::HDF,
        pcf::PCF,
        transport::TransportMessage,
    },
};

/// Streams Message comprised of a Header ([`HDF`]) and Payload([`PCF`])
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct Message<Content> {
    /// Header of the message
    header: HDF,
    /// Body of the message
    payload: PCF<Content>,
}

impl<Payload> Message<Payload> {
    /// Creates a new [`Message`] wrapper around the provided message components.
    ///
    /// # Arguments
    /// * `header`: The header of the message
    /// * `payload`: The body of te message
    pub fn new(header: HDF, payload: PCF<Payload>) -> Self {
        Self { header, payload }
    }

    /// Inject a header into the [`Message`] wrapper
    ///
    /// # Arguments
    /// * `header`: The header of the message
    pub fn with_header(&mut self, header: HDF) -> &mut Self {
        self.header = header;
        self
    }

    /// Inject a payload into the [`Message`] wrapper
    ///
    /// # Arguments
    /// * `payload`: The body of the message
    pub fn with_content(&mut self, content: Payload) -> &mut Self {
        self.payload.change_content(content);
        self
    }

    /// Returns a reference to the [`Message`] [header](`HDF`)
    pub fn header(&self) -> &HDF {
        &self.header
    }

    /// Returns a reference to the [`Message`] [payload](`PCF`)
    pub fn payload(&self) -> &PCF<Payload> {
        &self.payload
    }

    /// Consumes the [`Message`], returning the [payload](`PCF`)
    pub fn into_payload(self) -> PCF<Payload> {
        self.payload
    }

    /// Consumes the [`Message`], returning a tuple comprised of the [header](`HDF`) and
    /// [payload](`PCF`)
    pub fn into_parts(self) -> (HDF, PCF<Payload>) {
        (self.header, self.payload)
    }

    /// Encodes the message for transport, wrapping the [`HDF`] and [`PCF`] into one binary message,
    /// returning that [`TransportMessage`] and the context [`Spongos`] state.
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
