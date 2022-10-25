// Rust
use core::fmt;

// IOTA

// Streams
use spongos::{ddml::commands::unwrap, KeccakF1600, Spongos, PRP};

// Local
use crate::{
    error::Result,
    message::{content::ContentUnwrap, hdf::HDF, message::Message, pcf::PCF, transport::TransportMessage},
};

/// Message context preparsed for unwrapping.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PreparsedMessage<F = KeccakF1600> {
    /// The message bytes wrapper
    transport_msg: TransportMessage,
    /// Parsed header of the message
    header: HDF,
    /// Spongos state for the `Context` of the pre-parsed message
    spongos: Spongos<F>,
    /// Streaming position within `Context`, marking the end of the `HDF` and beginning of the
    /// `PCF`. Used in partial processing.
    cursor: usize,
}

impl<F> PreparsedMessage<F> {
    /// Create a new [`PreparsedMessage`] wrapper around a [`TransportMessage`] after the header has
    /// been parsed from the message context.
    ///
    /// # Arguments
    /// * `transport_msg`: The message wrapper that has been preparsed
    /// * `header`: The `HDF` parsed from the transport message
    /// * `spongos`: The `Context` state following the `HDF` parsing
    /// * `cursor`: The read position of the `Context` stream following the `HDF` parsing
    pub(crate) fn new(transport_msg: TransportMessage, header: HDF, spongos: Spongos<F>, cursor: usize) -> Self {
        Self {
            transport_msg,
            header,
            spongos,
            cursor,
        }
    }

    /// Returns a reference to the message [`HDF`]
    pub fn header(&self) -> &HDF {
        &self.header
    }

    /// Returns a reference to the raw [`TransportMessage`]
    pub fn transport_msg(&self) -> &TransportMessage {
        &self.transport_msg
    }

    /// Consumes the [`PreparsedMessage`], returning a tuple containing the message `HDF`, raw
    /// `TransportMessage` and read position cursor
    pub fn into_parts(self) -> (HDF, TransportMessage, Spongos<F>, usize) {
        (self.header, self.transport_msg, self.spongos, self.cursor)
    }

    /// Returns a reference to the message read state cursor
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Returns the remainder of the message bytes starting from the read position cursor as a slice
    fn remaining_message(&self) -> &[u8] {
        &self.transport_msg.as_ref()[self.cursor..]
    }

    /// Decode the `PCF` from the remainder of the message bytes, starting from the cursor position.
    /// Returns a new [`Message`] wrapper around the [`HDF`] and [`PCF`], as well as the spongos
    /// state following the unwrapping operations.
    ///
    /// # Arguments
    /// * `content` - An implementation of a [`PCF`] [`unwrap::Context`]
    pub async fn unwrap<Content>(self, content: Content) -> Result<(Message<Content>, Spongos<F>)>
    where
        for<'a> unwrap::Context<&'a [u8], F>: ContentUnwrap<PCF<Content>>,
        F: PRP,
    {
        let mut pcf = PCF::<()>::default().with_content(content);
        let spongos = self.spongos;
        let transport_msg = self.transport_msg;
        // Cannot use Self::remaining_message() due to partial move of spongos
        let mut ctx = unwrap::Context::new_with_spongos(&transport_msg.body()[self.cursor..], spongos);
        ctx.unwrap(&mut pcf).await?;
        // discard `self.ctx.stream` that should be empty
        let (spongos, _) = ctx.finalize();
        Ok((Message::new(self.header, pcf), spongos))
    }
}

impl<F> fmt::Debug for PreparsedMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{header: {:?}, ctx: {:?}}}",
            self.header,
            &self.remaining_message()[..10]
        )
    }
}
