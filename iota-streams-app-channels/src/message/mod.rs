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

/// Announcement Message Type
pub const ANNOUNCE: u8 = 0;
/// Keyload Message Type
pub const KEYLOAD: u8 = 1;
/// Sequence Message Type
pub const SEQUENCE: u8 = 2;
/// Signed Packet Message Type
pub const SIGNED_PACKET: u8 = 3;
/// Tagged Packet Message Type
pub const TAGGED_PACKET: u8 = 4;
/// Subscribe Message Type
pub const SUBSCRIBE: u8 = 5;
/// Unsubscribe Message Type
pub const UNSUBSCRIBE: u8 = 6;

// Unsubscribe message.
// pub mod unsubscribe;
