//! Streams message syntax version distinguished between incompatible changes in `DDML`
//! syntax and/or rules of processing `DDML` messages. It usually means that a new
//! command or type is added, or command proceeds in a different manner than before.
//! It can also signify changes in the `Header` message.
//!
//! Note, changes in syntax of Messages of a particular Application should be reflected
//! in `Header.content_type` field or the Content Message should implicitly support
//! versioning (ie. include `content_version` field for example).
//!
//! Streams message syntax version is indicated as the first byte in the binary encoded message.
//!
//! Backwards compatibility of the Streams implementations is welcome and not mandatory.

/// Streams version number.
pub(crate) const STREAMS_VER: u8 = 2;

/// Encoding Constants
pub(crate) const UTF8: u8 = 0;

/// HDF Frame Identifier
pub(crate) const HDF_ID: u8 = 4;
/// Initial PCF Frame Identifier
pub(crate) const INIT_PCF_ID: u8 = 5;
/// Intermediate PCF Frame Identifier
pub(crate) const INTER_PCF_ID: u8 = 12;
/// Final PCF Frame Identifier
pub(crate) const FINAL_PCF_ID: u8 = 14;
