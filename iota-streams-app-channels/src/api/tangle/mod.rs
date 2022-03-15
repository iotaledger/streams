//! Default parameters for Author and Subscriber types.

pub use futures;

pub use iota_streams_app::transport::tangle::MsgId;
use iota_streams_app::{
    id::Identifier,
    message::{
        self,
        BinaryBody,
    },
    transport::{
        self,
        tangle::{
            AppInst,
            DefaultTangleLinkGenerator,
            TangleAddress,
            TangleMessage,
        },
    },
};

#[cfg(any(feature = "client", feature = "wasm-client"))]
use iota_streams_app::transport::tangle::client::Details as ClientDetails;

pub use message::Cursor;
// Bring trait methods into scope publicly.
pub use message::LinkGenerator;

pub use super::ChannelType;
use super::DefaultF;
use iota_streams_core::psk;
use iota_streams_ddml::link_store::DefaultLinkStore;
pub use iota_streams_ddml::types::Bytes;

use crypto::{
    keys::x25519,
    signatures::ed25519,
};

/// Identifiers for Pre-Shared Keys
pub type PskIds = psk::PskIds;

/// Tangle Address Link type.
pub type Address = TangleAddress;
/// Tangle Address representing Channel Application Instance.
pub type ChannelAddress = AppInst;

/// Binary encoded message type.
pub type Message = TangleMessage;
// Details for a message on our tangle transport
#[cfg(any(feature = "client", feature = "wasm-client"))]
pub type Details = ClientDetails;

/// Wrapped Message for sending and commit
pub type WrappedMessage = message::WrappedMessage<DefaultF, Address>;
/// Wrapped Spongos state with Address identifier
pub type WrapState = message::WrapState<DefaultF, Address>;
/// Wrapper for optional sequence message and state
pub type WrappedSequence = super::user::WrappedSequence<DefaultF, Address>;
/// Ed25519 Public Key
pub type PublicKey = ed25519::PublicKey;
pub type ExchangeKey = x25519::PublicKey;
pub const PUBLIC_KEY_LENGTH: usize = ed25519::PUBLIC_KEY_LENGTH;

/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

/// Sequence State information
pub type SeqState = Cursor<MsgId>;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Link Store.
pub type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<Address, Message>;

/// Transportation trait for Tangle Client implementation
// TODO: Use trait synonyms `pub Transport = transport::Transport<DefaultF, Address>;`.
pub trait Transport: transport::Transport<Address, Message> + Clone {}
impl<T> Transport for T where T: transport::Transport<Address, Message> + Clone {}

mod msginfo;
pub use msginfo::MsgInfo;

// SignedPacket is 240 bytes in stack (192 + 24 + 24), which means 5 times more than
// the next biggest variant (TaggedPacket, 48 bytes), and the impossibility of inlining.
// Boxing PublicKey would usually be a net performance improvement if SignedPacket wasn't frequent.
// However, chances are it is the most frequent variant, therefore a profile must confirm there's
// enough performance improvement to justify the ergonomic drawback of re-enabling this lint
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
/// Message body returned as part of handle message routine.
pub enum MessageContent {
    Announce,
    Keyload,
    SignedPacket {
        id: Identifier,
        public_payload: Bytes,
        masked_payload: Bytes,
    },
    TaggedPacket {
        public_payload: Bytes,
        masked_payload: Bytes,
    },
    Sequence,
    Subscribe,
    Unsubscribe,
    Unreadable(BinaryMessage),
}

impl MessageContent {
    pub fn new_announce() -> Self {
        Self::Announce
    }

    pub fn new_keyload() -> Self {
        Self::Keyload
    }

    pub fn new_signed_packet<P, M>(id: Identifier, public_payload: P, masked_payload: M) -> Self
    where
        P: Into<Bytes>,
        M: Into<Bytes>,
    {
        Self::SignedPacket {
            id,
            public_payload: public_payload.into(),
            masked_payload: masked_payload.into(),
        }
    }

    pub fn new_tagged_packet<P, M>(public_payload: P, masked_payload: M) -> Self
    where
        P: Into<Bytes>,
        M: Into<Bytes>,
    {
        Self::TaggedPacket {
            public_payload: public_payload.into(),
            masked_payload: masked_payload.into(),
        }
    }

    pub fn unreadable(binary: BinaryMessage) -> Self {
        Self::Unreadable(binary)
    }

    pub fn is_announce(&self) -> bool {
        matches!(self, MessageContent::Announce)
    }

    pub fn is_keyload(&self) -> bool {
        matches!(self, MessageContent::Keyload)
    }

    pub fn is_signed_packet(&self) -> bool {
        matches!(self, MessageContent::SignedPacket { .. })
    }

    pub fn is_tagged_packet(&self) -> bool {
        matches!(self, MessageContent::TaggedPacket { .. })
    }

    pub fn is_sequence(&self) -> bool {
        matches!(self, MessageContent::Sequence)
    }

    pub fn is_subscribe(&self) -> bool {
        matches!(self, MessageContent::Subscribe)
    }

    pub fn is_unsubscribe(&self) -> bool {
        matches!(self, MessageContent::Unsubscribe)
    }

    pub fn is_unreadable(&self) -> bool {
        matches!(self, MessageContent::Unreadable(..))
    }

    /// Get the public payload of the message
    ///
    /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
    /// it returns `Some(payload)`, otherwise returns `None`.  
    pub fn public_payload(&self) -> Option<&Bytes> {
        match self {
            Self::TaggedPacket { public_payload, .. } | Self::SignedPacket { public_payload, .. } => {
                Some(public_payload)
            }
            _ => None,
        }
    }

    /// Get the masked payload of the message
    ///
    /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
    /// it returns `Some(payload)`, otherwise returns `None`.  
    pub fn masked_payload(&self) -> Option<&Bytes> {
        match self {
            Self::TaggedPacket { masked_payload, .. } | Self::SignedPacket { masked_payload, .. } => {
                Some(masked_payload)
            }
            _ => None,
        }
    }
}

/// Generic unwrapped message type containing possible message contents
pub type UnwrappedMessage = message::GenericMessage<Address, MessageContent>;

/// Generic binary message type for sequence handling
pub type BinaryMessage = message::GenericMessage<Address, BinaryBody>;

mod user;
/// User object storing the Auth/Sub implementation as well as the transport instance
pub use user::User;

mod messages;
pub use messages::{
    IntoMessages,
    Messages,
};

mod author;
/// Tangle-specific Channel Author type.
pub use author::Author;

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
