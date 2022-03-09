//! Streams Protocol message types and encodings

/// Announce message.
mod announce;

/// Keyload message.
mod keyload;

/// SignedPacket message.
mod signed_packet;

/// TaggedPacket message.
mod tagged_packet;

/// Subscribe message.
mod subscribe;

/// Sequence message.
mod sequence;

/// Unsubscribe message.
mod unsubscribe;

// TODO: WHAT IS THIS DOING HERE?
/// Announcement Message Type
const ANNOUNCE: u8 = 0;
/// Keyload Message Type
const KEYLOAD: u8 = 1;
/// Sequence Message Type
const SEQUENCE: u8 = 2;
/// Signed Packet Message Type
const SIGNED_PACKET: u8 = 3;
/// Tagged Packet Message Type
const TAGGED_PACKET: u8 = 4;
/// Subscribe Message Type
const SUBSCRIBE: u8 = 5;
/// Unsubscribe Message Type
const UNSUBSCRIBE: u8 = 6;
