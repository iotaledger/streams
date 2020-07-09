/// Reexport sponge `Mode`.
//pub use crate::sponge::spongos::Mode;
use std::convert::{
    From,
};

/// Pseudo-random permutation.
///
/// Actually, it may be non-bijective as the inverse transform is not used in sponge construction.
pub trait PRP: Sized + Default + Clone + From<Vec<u8>> + Into<Vec<u8>> {
    /// Size of the outer state in bytes.
    /// In other words, size of data chunk that PRP can process in one transform.
    const RATE: usize;

    /// Size of the inner state in bits, determines the security of sponge constructions.
    /// Other sizes such as sizes of hash/key/nonce/etc. are derived from the capacity.
    const CAPACITY_BITS: usize;

    /// Inject outer state, transform full state, eject new outer state.
    fn transform(&mut self, outer: &mut [u8]);
}
