//! `TaggedPacket` message content. The message has a plain and masked payload and is authenticated
//! with MAC.
//!
//! The message may be linked to any other message in the channel and can be published by any
//! participant in a channel.
//!
//! ```ddml
//! message TaggedPacket {
//!     join link msgid;
//!     absorb bytes public_payload;
//!     mask bytes masked_payload;
//!     commit;
//!     squeeze byte mac[32];
//! }
//! ```
// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Join,
            Mask,
            Squeeze,
        },
        io,
        types::{
            Bytes,
            Mac,
        },
    },
    Spongos,
    PRP,
};
use LETS::{
    id::Identifier,
    message::{
        ContentSizeof,
        ContentUnwrap,
        ContentWrap,
    },
};

// Local

const MAC: Mac = Mac::new(32);

pub(crate) struct Wrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: &'a [u8],
    masked_payload: &'a [u8],
}

impl<'a, F> Wrap<'a, F> {
    pub(crate) fn new(initial_state: &'a mut Spongos<F>, public_payload: &'a [u8], masked_payload: &'a [u8]) -> Self {
        Self {
            initial_state,
            public_payload,
            masked_payload,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<Wrap<'a, F>> for sizeof::Context {
    async fn sizeof(&mut self, tagged_packet: &Wrap<'a, F>) -> Result<&mut Self> {
        self.absorb(&Bytes::new(tagged_packet.public_payload))?
            .mask(&Bytes::new(tagged_packet.masked_payload))?
            .commit()?
            .squeeze(&MAC)?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, OS> ContentWrap<Wrap<'a, F>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    async fn wrap(&mut self, tagged_packet: &mut Wrap<'a, F>) -> Result<&mut Self> {
        self.join(tagged_packet.initial_state)?
            .absorb(&Bytes::new(tagged_packet.public_payload))?
            .mask(&Bytes::new(tagged_packet.masked_payload))?
            .commit()?
            .squeeze(&MAC)?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: Vec<u8>,
    masked_payload: Vec<u8>,
}

impl<'a, F> Unwrap<'a, F> {
    pub(crate) fn new(initial_state: &'a mut Spongos<F>) -> Self {
        Self {
            initial_state,
            public_payload: Default::default(),
            masked_payload: Default::default(),
        }
    }

    pub(crate) fn take_masked_payload(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.masked_payload)
    }

    pub(crate) fn take_public_payload(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.public_payload)
    }
}

#[async_trait(?Send)]
impl<'a, F, IS> ContentUnwrap<Unwrap<'a, F>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, tagged_packet: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        self.join(tagged_packet.initial_state)?
            .absorb(Bytes::new(&mut tagged_packet.public_payload))?
            .mask(Bytes::new(&mut tagged_packet.masked_payload))?
            .commit()?
            .squeeze(&MAC)?;
        Ok(self)
    }
}
