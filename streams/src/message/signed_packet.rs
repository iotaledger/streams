//! `SignedPacket` message _wrapping_ and _unwrapping_.
//!
//! `SignedPacket` messages contain a plain and a masked payload, signed by the sender.
//!
//! ```ddml
//! message SignedPacket {
//!     skip                link    msgid;
//!     join(msgid);
//!     absorb              u8      ed25519_pubkey[32];
//!     absorb              uint    public_size;
//!     absorb              u8      public_payload[public_size];
//!     mask                uint    masked_size;
//!     mask                u8      masked_payload[masked_size];
//!     commit;
//!     squeeze external    u8      hash[64];
//!     ed25519(hash)       u8      signature[64];
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
use crypto::signatures::ed25519;

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Join,
            Mask,
        },
        io,
        types::Bytes,
    },
    Spongos,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
    },
    message::{
        ContentSign,
        ContentSignSizeof,
        ContentSizeof,
        ContentUnwrap,
        ContentVerify,
        ContentWrap,
    },
};

// Local

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     sponge::prp::PRP,
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

struct Wrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: &'a [u8],
    masked_payload: &'a [u8],
    user_id: &'a Identity,
}

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<Wrap<'a, F>> for sizeof::Context {
    async fn sizeof(&mut self, signed_packet: &Wrap<'a, F>) -> Result<&mut Self> {
        self.sizeof(&signed_packet.user_id.to_identifier())
            .await?
            .absorb(&Bytes::new(signed_packet.public_payload))?
            .mask(&Bytes::new(signed_packet.masked_payload))?
            .sign_sizeof(signed_packet.user_id)
            .await?;
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
            .wrap(&mut signed_packet.user_id.to_identifier())
            .await?
            .absorb(&Bytes::new(signed_packet.public_payload))?
            .mask(&Bytes::new(signed_packet.masked_payload))?
            .sign(signed_packet.user_id)
            .await?;
        Ok(self)
    }
}

pub struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    public_payload: Vec<u8>,
    masked_payload: Vec<u8>,
    user_id: Identifier,
}

impl<'a, F> Unwrap<'a, F> {
    fn new(initial_state: &'a mut Spongos<F>) -> Self {
        Self {
            initial_state,
            public_payload: Default::default(),
            masked_payload: Default::default(),
            user_id: Identifier::default(),
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
            .unwrap(&mut signed_packet.user_id)
            .await?
            .absorb(&mut Bytes::new(&mut signed_packet.public_payload))?
            .mask(&mut Bytes::new(&mut signed_packet.masked_payload))?
            .verify(&signed_packet.user_id)
            .await?;
        Ok(self)
    }
}
