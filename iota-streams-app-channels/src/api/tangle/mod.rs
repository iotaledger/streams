//! Default parameters for Author and Subscriber types.

use iota_streams_app::{
    message,
    transport::{
        self,
        tangle::*,
    },
};
use iota_streams_core::psk;
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;
use iota_streams_ddml::{
    types as pb3_types,
    types::DefaultLinkStore,
};

/// Default spongos PRP.
pub type DefaultF = KeccakF1600;

/// Default Tbit & PSK & MSS & NTRU types.
pub type Bytes = pb3_types::Bytes;
pub type PskIds = psk::PskIds;

/// Link type.
pub type Address = TangleAddress;
/// Channel address.
pub type ChannelAddress = AppInst;

/// Tbinary encoded message type.
pub type Message = message::TbinaryMessage<DefaultF, Address>;
/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<DefaultF, Address>;

pub trait Transport: transport::Transport<DefaultF, Address> {}

impl<T> Transport for T where T: transport::Transport<DefaultF, Address> {}

/// Message associated info, just message type indicator.
#[derive(Copy, Clone)]
pub enum MsgInfo {
    Announce,
    ChangeKey,
    Keyload,
    SignedPacket,
    TaggedPacket,
    Subscribe,
    Unsubscribe,
    Sequence,
}

/// Link Store.
pub type Store = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

mod author;
mod subscriber;

/// Tangle-specific Channel Author type.
pub use author::Author;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
