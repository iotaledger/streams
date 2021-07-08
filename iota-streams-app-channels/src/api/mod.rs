/// Public Key storage. Used for keeping track of channel state
pub mod pk_store;

/// Pre Shared Key storage. Used for storing a map of Pre Shared Keys and Identifiers
pub mod psk_store;

/// We would need an array import in prelude, and using IntoIter with size specifying...
/// type_complexity to be determined in future issue

/// Base level api for user implementation
#[allow(clippy::ptr_arg, clippy::type_complexity)]
pub mod user;

/// Tangle-specific Channel API.
#[cfg(all(feature = "tangle"))]
pub mod tangle;

use iota_streams_core::psk::*;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;

/// Makes a PSK from an arbitrary byte array
pub fn make_psk(bytes: &[u8]) -> Psk {
    psk_from_seed::<KeccakF1600>(bytes)
}

/// Makes a PskId from an arbitrary byte array
pub fn make_pskid(bytes: &[u8]) -> PskId {
    pskid_from_seed::<KeccakF1600>(bytes)
}