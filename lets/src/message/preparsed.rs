// Rust
use core::fmt;

// IOTA

// Streams
use spongos::{ddml::commands::unwrap, KeccakF1600, Spongos, PRP};

// Local
use crate::{
    error::{Result},
    message::{content::ContentUnwrap, hdf::HDF, message::Message, pcf::PCF, transport::TransportMessage},
};

/// Message context preparsed for unwrapping.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PreparsedMessage<F = KeccakF1600> {
    transport_msg: TransportMessage,
    header: HDF,
    spongos: Spongos<F>,
    cursor: usize,
}

impl<F> PreparsedMessage<F> {
    pub(crate) fn new(transport_msg: TransportMessage, header: HDF, spongos: Spongos<F>, cursor: usize) -> Self {
        Self {
            transport_msg,
            header,
            spongos,
            cursor,
        }
    }

    pub fn header(&self) -> &HDF {
        &self.header
    }

    pub fn transport_msg(&self) -> &TransportMessage {
        &self.transport_msg
    }

    pub fn into_parts(self) -> (HDF, TransportMessage, Spongos<F>, usize) {
        (self.header, self.transport_msg, self.spongos, self.cursor)
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    fn remaining_message(&self) -> &[u8] {
        &self.transport_msg.as_ref()[self.cursor..]
    }

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
