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

use iota_streams_ddml::types::Uint8;

pub const ANNOUNCE: Uint8 = Uint8(0);
pub const KEYLOAD: Uint8 = Uint8(1);
pub const SEQUENCE: Uint8 = Uint8(2);
pub const SIGNED_PACKET: Uint8 = Uint8(3);
pub const TAGGED_PACKET: Uint8 = Uint8(4);
pub const SUBSCRIBE: Uint8 = Uint8(5);
pub const UNSUBSCRIBE: Uint8 = Uint8(6);

// Unsubscribe message.
// pub mod unsubscribe;
