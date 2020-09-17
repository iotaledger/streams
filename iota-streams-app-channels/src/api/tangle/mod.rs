//! Default parameters for Author and Subscriber types.

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
    types as ddml_types,
    link_store::DefaultLinkStore,
};
use super::{PublicKeyMap, PresharedKeyMap};

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
/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

pub type SeqState = (TangleAddress, usize);
pub type PkStore = PublicKeyMap<SeqState>;
pub type PskStore = PresharedKeyMap;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

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

/// Link Store.
pub type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<DefaultF, Address>;

pub trait Transport: transport::Transport<DefaultF, Address> {}

impl<T> Transport for T where T: transport::Transport<DefaultF, Address> {}

mod author;
/// Tangle-specific Channel Author type.
pub use author::Author;

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
