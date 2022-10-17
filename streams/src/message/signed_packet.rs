//! `SignedPacket` message _wrapping_ and _unwrapping_.
//!
//! `SignedPacket` messages contain a plain and a masked payload, signed by the sender.
//!
//! ```ddml
//! message SignedPacket {
//!     join(spongos);
//!     mask                u8      identifier;
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
use alloc::{boxed::Box, vec::Vec};

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams
use lets::{
    id::{Identifier, Identity},
    message::{ContentSign, ContentSignSizeof, ContentSizeof, ContentUnwrap, ContentVerify, ContentWrap},
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Join, Mask},
        io,
        types::Bytes,
    },
    error::Result,
    Spongos,
};

// Local

/// A struct that holds references needed for signed packet message encoding
pub(crate) struct Wrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// Payload slice that will not be masked
    public_payload: &'a [u8],
    /// Payload slice that will be masked
    masked_payload: &'a [u8],
    /// The [`Identity`] of the publisher
    user_id: &'a Identity,
}

impl<'a> Wrap<'a> {
    /// Creates a new [`Wrap`] struct for a signed packet message
    ///
    /// # Arguments:
    /// * `initial_state`: The initial [`Spongos`] state the message will be joined to
    /// * `user_id`: The [`Identity`] of the publishing user.
    /// * `public_payload`: A payload that will not be masked.
    /// * `masked_payload`: A payload taht will be masked.
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
        user_id: &'a Identity,
        public_payload: &'a [u8],
        masked_payload: &'a [u8],
    ) -> Self {
        Self {
            initial_state,
            user_id,
            public_payload,
            masked_payload,
        }
    }
}

#[async_trait(?Send)]
impl<'a> ContentSizeof<Wrap<'a>> for sizeof::Context {
    async fn sizeof(&mut self, signed_packet: &Wrap<'a>) -> Result<&mut Self> {
        self.mask(signed_packet.user_id.identifier())?
            .absorb(Bytes::new(signed_packet.public_payload))?
            .mask(Bytes::new(signed_packet.masked_payload))?
            .sign_sizeof(signed_packet.user_id)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, OS> ContentWrap<Wrap<'a>> for wrap::Context<OS>
where
    OS: io::OStream,
{
    async fn wrap(&mut self, signed_packet: &mut Wrap<'a>) -> Result<&mut Self> {
        self.join(signed_packet.initial_state)?
            .mask(signed_packet.user_id.identifier())?
            .absorb(Bytes::new(signed_packet.public_payload))?
            .mask(Bytes::new(signed_packet.masked_payload))?
            .sign(signed_packet.user_id)
            .await?;
        Ok(self)
    }
}

/// A struct that holds the placeholders needed for signed packet message decoding
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct Unwrap<'a> {
    /// The base [`Spongos`] state that the message will be joined to
    initial_state: &'a mut Spongos,
    /// A payload that was not masked
    public_payload: Vec<u8>,
    /// A payload that was masked
    masked_payload: Vec<u8>,
    /// The [`Identifier`] of the publisher
    publisher_id: Identifier,
}

impl<'a> Unwrap<'a> {
    /// Creates a new [`Unwrap`] struct for a signed packet message
    ///
    /// # Arguments
    /// * `initial_state`: The base [`Spongos`] state that the message will be joined to
    pub(crate) fn new(initial_state: &'a mut Spongos) -> Self {
        Self {
            initial_state,
            public_payload: Default::default(),
            masked_payload: Default::default(),
            publisher_id: Identifier::default(),
        }
    }

    /// Consumes the [`Unwrap`], returning the [`Identifier`] of the publisher
    pub(crate) fn into_publisher_identifier(self) -> Identifier {
        self.publisher_id
    }

    /// Takes the payload that was masked from the [`Unwrap`]
    pub(crate) fn take_masked_payload(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.masked_payload)
    }

    /// Takes the payload that was not masked from the [`Unwrap`]
    pub(crate) fn take_public_payload(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.public_payload)
    }
}

#[async_trait(?Send)]
impl<'a, IS> ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, signed_packet: &mut Unwrap) -> Result<&mut Self> {
        self.join(signed_packet.initial_state)?
            .mask(&mut signed_packet.publisher_id)?
            .absorb(Bytes::new(&mut signed_packet.public_payload))?
            .mask(Bytes::new(&mut signed_packet.masked_payload))?
            .verify(&signed_packet.publisher_id)
            .await?;
        Ok(self)
    }
}
