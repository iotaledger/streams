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
    TransportMessage,
};

/// Message context preparsed for unwrapping.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PreparsedMessage<T, F, Address> {
    transport_msg: TransportMessage<T>,
    header: HDF<Address>,
    spongos: Spongos<F>,
    cursor: usize,
}

impl<T, F, Address> PreparsedMessage<T, F, Address> {
    pub(crate) fn new(
        transport_msg: TransportMessage<T>,
        header: HDF<Address>,
        spongos: Spongos<F>,
        cursor: usize,
    ) -> Self {
        Self {
            transport_msg,
            header,
            spongos,
            cursor,
        }
    }

    fn is_message_type(&self, content_type: u8) -> bool {
        self.header().message_type() == content_type
    }

    pub fn message_type(&self) -> u8 {
        self.header().message_type()
    }

    pub fn linked_msg_address(&self) -> &Option<Address> {
        self.header().linked_msg_address()
    }

    fn header(&self) -> &HDF<Address> {
        &self.header
    }

    pub fn take_header(&mut self) -> HDF<Address>
    where
        Address: Default,
    {
        core::mem::take(&mut self.header)
    }

    pub fn transport_msg(&self) -> &TransportMessage<T> {
        &self.transport_msg
    }

    pub fn into_transport_msg(self) -> TransportMessage<T> {
        self.transport_msg
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    fn remaining_message(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        &self.transport_msg.body().as_ref()[self.cursor..]
    }

    pub async fn unwrap<Content>(self, content: Content) -> Result<(Message<Address, Content>, Spongos<F>)>
    where
        for<'a> unwrap::Context<F, &'a [u8]>: ContentUnwrap<PCF<Content>>,
        T: AsRef<[u8]>,
        F: PRP,
    {
        let mut pcf = PCF::<()>::default().with_content(content);
        let spongos = self.spongos;
        // Cannot use Self::remaining_message() due to partial move of spongos
        let transport_msg = self.transport_msg;
        let mut ctx = unwrap::Context::new_with_spongos(&transport_msg.body().as_ref()[self.cursor..], spongos);
        ctx.unwrap(&mut pcf).await?;
        // Commit Spongos and discard `self.ctx.stream` that should be empty
        let (spongos, cursor) = ctx.finalize();
        Ok((Message::new(self.header, pcf), spongos))
    }
}

impl<T, F, Link> fmt::Debug for PreparsedMessage<T, F, Link>
where
    Link: fmt::Debug,
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{header: {:?}, ctx: {:?}}}",
            self.header,
            &self.remaining_message()[..10]
        )
    }
}
