//! Channel Application messages.

/// Announce message.
pub mod announce;

/// Keyload message.
pub mod keyload;

/// SignedPacket message.
pub mod signed_packet;

/// TaggedPacket message.
pub mod tagged_packet;

/// Subscribe message.
pub mod subscribe;

/// Sequence message.
pub mod sequence;

pub const ANNOUNCE: u8 = 0;
pub const KEYLOAD: u8 = 1;
pub const SEQUENCE: u8 = 2;
pub const SIGNED_PACKET: u8 = 3;
pub const TAGGED_PACKET: u8 = 4;
pub const SUBSCRIBE: u8 = 5;
pub const UNSUBSCRIBE: u8 = 6;

// Unsubscribe message.
// pub mod unsubscribe;
