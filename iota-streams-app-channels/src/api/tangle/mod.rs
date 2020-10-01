//! Default parameters for Author and Subscriber types.

use super::{
    PresharedKeyMap,
    PublicKeyMap,
    SequencingState,
};
use core::fmt;
use iota_streams_app::{
    message,
    transport::{
        self,
        tangle::*,
    },
};
use iota_streams_core::psk;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;
use iota_streams_ddml::{
    link_store::DefaultLinkStore,
    types as ddml_types,
};

use iota_streams_core_edsig::signature::ed25519;

/// Default spongos PRP.
pub type DefaultF = KeccakF1600;

/// Default Tbit & PSK & MSS & NTRU types.
pub type Bytes = ddml_types::Bytes;
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

pub type SeqState = SequencingState<MsgId>;
pub type PkStore = PublicKeyMap<SeqState>;
pub type PskStore = PresharedKeyMap;

impl fmt::Display for SeqState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{},{}>", self.0, self.1)
    }
}

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Link Store.
pub type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<DefaultF, Address>;

pub trait Transport: transport::Transport<DefaultF, Address> {}

impl<T> Transport for T where T: transport::Transport<DefaultF, Address> {}

mod author;
/// Tangle-specific Channel Author type.
pub use author::Author;

pub mod user;
/// User object storing the Auth/Sub implementation as well as the transport instance
pub use user::User;

#[derive(PartialEq)]
pub enum UserType {
    Author,
    Subscriber
}

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

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
