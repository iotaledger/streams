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
use alloc::{boxed::Box, vec::Vec};

// 3rd-party
use async_trait::async_trait;
use anyhow::Result;

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, wrap, unwrap, Absorb, Mask, Commit, Squeeze, Join},
        types::{Mac, Bytes},
        io,
    },
    PRP, Spongos,
};
use LETS::message::{
    ContentSizeof, ContentWrap, ContentUnwrap
};

// Local
// use iota_streams_core::{
//     async_trait,
//     prelude::{
//         typenum::Unsigned as _,
//         Box,
//     },
//     sponge::{
//         prp::PRP,
//         spongos,
//     },
//     Result,
// };
// use iota_streams_ddml::{
//     command::*,
//     io,
//     link_store::{
//         EmptyLinkStore,
//         LinkStore,
//     },
//     types::*,
// };

const MAC: Mac = Mac::new(32);

pub struct Wrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: &'a [u8],
    masked_payload: &'a [u8],
}

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<Wrap<'a, F>> for sizeof::Context {
    async fn sizeof(&mut self, signed_packet: &Wrap<'a, F>) -> Result<&mut Self> {
        self
            .absorb(&Bytes::new(signed_packet.public_payload))?
            .mask(&Bytes::new(signed_packet.masked_payload))?
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
    async fn wrap(&mut self, signed_packet: &mut Wrap<'a, F>) -> Result<&mut Self> {
        self.join(signed_packet.initial_state)?
            .absorb(&Bytes::new(signed_packet.public_payload))?
            .mask(&Bytes::new(signed_packet.masked_payload))?
            .commit()?
            .squeeze(&MAC)?;
        Ok(self)
    }
}

pub struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: Vec<u8>,
    masked_payload: Vec<u8>,
}

impl<'a, F> Unwrap<'a, F> {
    fn new(initial_state: &'a mut Spongos<F>) -> Self {
        Self {
            initial_state,
            public_payload: Default::default(),
            masked_payload: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl<'a, F, IS> ContentUnwrap<Unwrap<'a, F>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, signed_packet: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        self.join(signed_packet.initial_state)?
            .absorb(&mut Bytes::new(&mut signed_packet.public_payload))?
            .mask(&mut Bytes::new(&mut signed_packet.masked_payload))?
            .commit()?
            .squeeze(&MAC)?;
        Ok(self)
    }
}