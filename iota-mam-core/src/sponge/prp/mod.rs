use crate::tbits::slice::*;

/// Pseudo-random permutation.
///
/// Actually, it may be non-bijective as the inverse transform is not used in sponge construction.
pub trait PRP<TW> {
    /// Size of the outer state in tbits.
    const RATE: usize;

    /// Inject outer state, transform full state, eject new outer state.
    fn transform(&mut self, outer: &mut TbitSliceMutT<TW>);
}

mod troika;

pub use troika::Troika;
//use crate::tbits::word::BasicTbitWord;
use crate::tbits::trinary::{Trit, TritWord};

//TODO: Implement binary adapter for Troika.

impl<TW> PRP<TW> for Troika where TW: TritWord {
    const RATE: usize = 486;

    fn transform(&mut self, outer: &mut TbitSliceMutT<TW>) {
        debug_assert_eq!(<Self as PRP<TW>>::RATE, outer.total_size());

        unsafe {
            // move trits from outer[0..d) to Troika state
            let mut o = outer.as_const().dropped();
            let n = o.size();
            for idx in 0..n {
                self.set1(idx, o.get_trit().0);
                o = o.drop(1);
            }
            //TODO: should the rest of the outer state be zeroized/padded before permutation?
        }

        self.permutation();
        // This should be safe as `outer` is the only ref to the trits.
        unsafe { outer.pickup_all_mut(); }

        {
            // move trits from Troika state to outer[0..rate]
            let n = outer.size();
            for idx in 0..n {
                outer.put_trit(Trit(self.get1(idx)));
                outer.advance(1);
            }
        }
    }
}

