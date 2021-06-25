pub mod key_store;

/// We would need an array import in prelude, and using IntoIter with size specifying...
/// type_complexity to be determined in future issue
#[allow(clippy::ptr_arg, clippy::type_complexity)]
pub mod user;

/// Tangle-specific Channel API.
#[cfg(all(feature = "tangle"))]
pub mod tangle;

#[derive(Clone)]
pub enum ChannelType {
    SingleBranch,
    MultiBranch,
    SingleDepth,
}

use iota_streams_core::psk::*;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;

/// Makes a PSK from an arbitrary byte array
pub fn make_psk(bytes: &[u8]) -> Psk {
    new_psk::<KeccakF1600>(bytes)
}

/// Makes a PskId from an arbitrary byte array
pub fn make_pskid(bytes: &[u8]) -> PskId {
    new_pskid::<KeccakF1600>(bytes)
}
