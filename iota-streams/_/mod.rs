//! Default parameters for Author and Subscriber types.

use futures;

use iota_streams_app::transport::tangle::MsgId;
use iota_streams_app::{
    id::Identifier,
    message::{
        self,
        BinaryBody,
    },
    transport::tangle::{
        AppInst,
        DefaultTangleLinkGenerator,
        TangleAddress,
    },
};

#[cfg(any(feature = "client", feature = "wasm-client"))]
use iota_streams_app::transport::tangle::client::Details as ClientDetails;

use message::Cursor;
// Bring trait methods into scope publicly.
use message::LinkGenerator;

use super::{
    Address,
    DefaultF,
    Message,
    Transport,
};
use iota_streams_core::psk;
use iota_streams_ddml::link_store::DefaultLinkStore;
use iota_streams_ddml::types::Bytes;

use crypto::{
    keys::x25519,
    signatures::ed25519,
};

/// Identifiers for Pre-Shared Keys
type PskIds = psk::PskIds;

/// Tangle Address representing Channel Application Instance.
type ChannelAddress = AppInst;

// Details for a message on our tangle transport
#[cfg(any(feature = "client", feature = "wasm-client"))]
type Details = ClientDetails;

/// Wrapped Message for sending and commit
type WrappedMessage = message::WrappedMessage<DefaultF, Address>;
/// Wrapped Spongos state with Address identifier
type WrapState = message::WrapState<DefaultF, Address>;
/// Wrapper for optional sequence message and state
type WrappedSequence = super::user::WrappedSequence<DefaultF, Address>;
/// Ed25519 Public Key
type PublicKey = ed25519::PublicKey;
type ExchangeKey = x25519::PublicKey;
const PUBLIC_KEY_LENGTH: usize = ed25519::PUBLIC_KEY_LENGTH;

/// Message type with parsed header.
type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

/// Sequence State information
type SeqState = Cursor<MsgId>;

/// Link Generator specifies algorithm for generating new message addressed.
type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Link Store.
type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

mod msginfo;
use msginfo::MsgInfo;

// SignedPacket is 240 bytes in stack (192 + 24 + 24), which means 5 times more than
// the next biggest variant (TaggedPacket, 48 bytes), and the impossibility of inlining.
// Boxing PublicKey would usually be a net performance improvement if SignedPacket wasn't frequent.
// However, chances are it is the most frequent variant, therefore a profile must confirm there's
// enough performance improvement to justify the ergonomic drawback of re-enabling this lint
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
/// Message body returned as part of handle message routine.
enum MessageContent {
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
    fn new_announce() -> Self {
        Self::Announce
    }

    fn new_keyload() -> Self {
        Self::Keyload
    }

    fn new_signed_packet<P, M>(id: Identifier, public_payload: P, masked_payload: M) -> Self
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

    fn new_tagged_packet<P, M>(public_payload: P, masked_payload: M) -> Self
    where
        P: Into<Bytes>,
        M: Into<Bytes>,
    {
        Self::TaggedPacket {
            public_payload: public_payload.into(),
            masked_payload: masked_payload.into(),
        }
    }

    fn unreadable(binary: BinaryMessage) -> Self {
        Self::Unreadable(binary)
    }

    fn is_announce(&self) -> bool {
        matches!(self, MessageContent::Announce)
    }

    fn is_keyload(&self) -> bool {
        matches!(self, MessageContent::Keyload)
    }

    fn is_signed_packet(&self) -> bool {
        matches!(self, MessageContent::SignedPacket { .. })
    }

    fn is_tagged_packet(&self) -> bool {
        matches!(self, MessageContent::TaggedPacket { .. })
    }

    fn is_sequence(&self) -> bool {
        matches!(self, MessageContent::Sequence)
    }

    fn is_subscribe(&self) -> bool {
        matches!(self, MessageContent::Subscribe)
    }

    fn is_unsubscribe(&self) -> bool {
        matches!(self, MessageContent::Unsubscribe)
    }

    fn is_unreadable(&self) -> bool {
        matches!(self, MessageContent::Unreadable(..))
    }

    /// Get the public payload of the message
    ///
    /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
    /// it returns `Some(payload)`, otherwise returns `None`.  
    fn public_payload(&self) -> Option<&Bytes> {
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
    fn masked_payload(&self) -> Option<&Bytes> {
        match self {
            Self::TaggedPacket { masked_payload, .. } | Self::SignedPacket { masked_payload, .. } => {
                Some(masked_payload)
            }
            _ => None,
        }
    }
}

/// Generic unwrapped message type containing possible message contents
type UnwrappedMessage = message::GenericMessage<Address, MessageContent>;

/// Generic binary message type for sequence handling
type BinaryMessage = message::GenericMessage<Address, BinaryBody>;

mod user;
/// User object storing the Auth/Sub implementation as well as the transport instance
use user::User;

mod messages;
use messages::{
    IntoMessages,
    Messages,
};

mod test;

mod user_builder;
use user_builder::UserBuilder;
