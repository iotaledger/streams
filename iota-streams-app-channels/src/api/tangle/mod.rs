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
pub type Message = message::BinaryMessage<DefaultF, Address>;

/// Wrapped Message for sending and commit
pub type WrappedMessage = message::WrappedMessage<DefaultF, Address>;

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
pub type BucketTransport = transport::BucketTransport<DefaultF, Address>;

// TODO: Use trait synonyms `pub Transport = transport::Transport<DefaultF, Address>;`.
pub trait Transport: transport::Transport<DefaultF, Address> {}
impl<T> Transport for T where T: transport::Transport<DefaultF, Address> {}

/// Message associated info, just message type indicator.
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

pub struct MessageReturn {
    pub pk: Option<PublicKey>,
    pub link: Address,
    pub public_payload: Bytes,
    pub masked_payload: Bytes,
}

impl MessageReturn {
    fn new(pk: Option<PublicKey>, link: Address, public_payload: Bytes, masked_payload: Bytes) -> Self {
        Self {
            pk,
            link,
            public_payload,
            masked_payload
        }
    }
}

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
