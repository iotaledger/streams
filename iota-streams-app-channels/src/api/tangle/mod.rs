//! Default parameters for Author and Subscriber types.

use super::{
    psk_store::PresharedKeyMap,
    pk_store::PublicKeyMap,
};
use iota_streams_app::{
    message,
    transport::{
        self,
        tangle::{
            AppInst,
            MsgId,
            TangleAddress,
            TangleMessage,
            DefaultTangleLinkGenerator,
        },
    },
};

pub use message::Cursor;
// Bring trait methods into scope publicly.
pub use transport::Transport as _;
pub use message::LinkGenerator as _;

use iota_streams_core::psk;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;
use iota_streams_ddml::{
    link_store::DefaultLinkStore,
};
pub use iota_streams_ddml::types::Bytes;

use iota_streams_core_edsig::signature::ed25519;

/// Default spongos PRP.
pub type DefaultF = KeccakF1600;

pub type PskIds = psk::PskIds;

/// Link type.
pub type Address = TangleAddress;
/// Channel address.
pub type ChannelAddress = AppInst;

/// Binary encoded message type.
pub type Message = TangleMessage<DefaultF>;

/// Wrapped Message for sending and commit
pub type WrappedMessage = message::WrappedMessage<DefaultF, Address>;
pub type WrapState = message::WrapState<DefaultF, Address>;
pub type WrappedSequence = super::user::WrappedSequence<DefaultF, Address>;
pub type WrapStateSequence = super::user::WrapStateSequence<DefaultF, Address>;

pub type PublicKey = ed25519::PublicKey;

/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

pub type SeqState = Cursor<MsgId>;
pub type PkStore = PublicKeyMap<SeqState>;
pub type PskStore = PresharedKeyMap;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Link Store.
pub type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<Address, Message>;

// TODO: Use trait synonyms `pub Transport = transport::Transport<DefaultF, Address>;`.
pub trait Transport: transport::Transport<Address, Message> {}
impl<T> Transport for T where T: transport::Transport<Address, Message> {}

/// Message associated info stored internally in User context, just message type indicator.
#[derive(Copy, Clone)]
pub enum MsgInfo {
    Announce,
    Keyload,
    SignedPacket,
    TaggedPacket,
    Subscribe,
    Unsubscribe,
    Sequence,
}

/// Message body returned as part of handle message routine.
pub enum MessageContent {
    Announce,
    Keyload,
    SignedPacket {
        pk: PublicKey,
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
}

impl MessageContent {
    pub fn new_announce() -> Self {
        Self::Announce
    }

    pub fn new_keyload() -> Self {
        Self::Keyload
    }

    pub fn new_signed_packet(pk: PublicKey, public_payload: Bytes, masked_payload: Bytes) -> Self {
        Self::SignedPacket {
            pk,
            public_payload,
            masked_payload
        }
    }

    pub fn new_tagged_packet(public_payload: Bytes, masked_payload: Bytes) -> Self {
        Self::TaggedPacket {
            public_payload,
            masked_payload
        }
    }
}

pub type UnwrappedMessage = message::GenericMessage<Address, MessageContent>;

mod user;
/// User object storing the Auth/Sub implementation as well as the transport instance
pub use user::User;

mod author;
/// Tangle-specific Channel Author type.
pub use author::Author;

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
