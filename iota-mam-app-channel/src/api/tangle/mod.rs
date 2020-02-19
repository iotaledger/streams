//! Default parameters for Author and Subscriber types.

use iota_mam_app::{message::*, transport::tangle::*};
use iota_mam_protobuf3::types::DefaultLinkStore;

/// Link type.
pub type Address = TangleAddress;

/// Message type.
pub type Message = TrinaryMessage<Address>;

/// Select Link Generator.
pub type LinkGen = DefaultTangleLinkGenerator;

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
pub type Store = DefaultLinkStore<MsgId, MsgInfo>;

pub mod author;
pub mod subscriber;
#[cfg(test)]
mod test;
