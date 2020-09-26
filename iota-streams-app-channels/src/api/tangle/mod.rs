//! Default parameters for Author and Subscriber types.

use super::{
    PresharedKeyMap,
    PublicKeyMap,
    SequencingState,
    MsgInfo,
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

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
