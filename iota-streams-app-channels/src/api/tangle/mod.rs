//! Default parameters for Author and Subscriber types.

use iota_streams_app::{
    message,
    transport::{
        self,
        tangle::*,
    },
};
use iota_streams_core::{
    psk,
    sponge::prp::troika::Troika,
    tbits::trinary::Trit,
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;
use iota_streams_protobuf3::{
    types as pb3_types,
    types::DefaultLinkStore,
};

/// Default tbit word encoding.
pub type DefaultTW = Trit;

/// Default spongos PRP.
pub type DefaultF = Troika;

/// Default MSS parameters.
pub type DefaultP = mss::troika::ParametersMtTraversal<DefaultTW>;

/// Default Tbit & PSK & MSS & NTRU types.
pub type Trytes = pb3_types::Trytes<DefaultTW>;
pub type PskIds = psk::PskIds<DefaultTW>;
pub type MssPublicKey = mss::PublicKey<DefaultTW, DefaultP>;
pub type MssPrivateKey = mss::PrivateKey<DefaultTW, DefaultP>;
pub type NtruPublicKey = ntru::PublicKey<DefaultTW, DefaultF>;
pub type NtruPrivateKey = ntru::PrivateKey<DefaultTW, DefaultF>;
pub type NtruPkids = ntru::NtruPkids<DefaultTW>;

/// Link type.
pub type Address = TangleAddress<DefaultTW>;
/// Channel address.
pub type ChannelAddress = AppInst<DefaultTW>;

/// Tbinary encoded message type.
pub type Message = message::TbinaryMessage<DefaultTW, DefaultF, Address>;
/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultTW, DefaultF, Address>;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultTW, DefaultF>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<DefaultTW, DefaultF, Address>;

pub trait Transport: transport::Transport<DefaultTW, DefaultF, Address> {}

impl<T> Transport for T where T: transport::Transport<DefaultTW, DefaultF, Address> {}

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
}

/// Link Store.
pub type Store = DefaultLinkStore<DefaultTW, DefaultF, MsgId<DefaultTW>, MsgInfo>;

mod author;
mod subscriber;

/// Tangle-specific Channel Author type.
pub use author::Author;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

#[cfg(test)]
mod test;
