/// Reexport sponge `Mode`.
pub use crate::sponge::spongos::Mode;
use crate::tbits::slice::*;
use std::convert::{
    From,
    Into,
};

/// Pseudo-random permutation.
///
/// Actually, it may be non-bijective as the inverse transform is not used in sponge construction.
pub trait PRP<TW>: Sized {
    /// Size of the outer state in tbits.
    const RATE: usize;

    /// Size of the inner state in tbits.
    /// Other sizes (such as sizes of hash/key/nonce/etc.) are derived from the capacity.
    const CAPACITY: usize;

    const MODE: Mode;

    /// Inject outer state, transform full state, eject new outer state.
    fn transform(&mut self, outer: &mut TbitSliceMut<TW>);

    type Inner: Into<Self> + From<Self>;
}
