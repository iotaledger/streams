pub mod inner;
mod prp;
pub use prp::*;

pub mod troika;
use troika::Troika;

use crate::tbits::{
    trinary::{Trit, TritWord},
    TbitSlice, TbitSliceMut, Tbits,
};

//TODO: Implement binary adapter for Troika.

impl Troika {
    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    fn to_inner<TW>(&self, mut inner: TbitSliceMut<TW>)
    where
        TW: TritWord, //BasicTbitWord<Tbit = Trit>,
    {
        //assert!(self.is_committed());
        assert_eq!(243, inner.size());
        //assert!(inner.size() <= 729);

        let n = inner.size();
        for idx in 729 - n..729 {
            inner.put_trit(Trit(self.get1(idx)));
            inner = inner.drop(1);
        }
    }

    fn to_inner_trits<TW>(&self) -> Tbits<TW>
    where
        TW: TritWord, //BasicTbitWord<Tbit = Trit>,
    {
        let mut inner = Tbits::<TW>::zero(243);
        self.to_inner(inner.slice_mut());
        inner
    }

    fn from_inner<TW>(mut inner: TbitSlice<TW>) -> Self
    where
        TW: TritWord, //BasicTbitWord<Tbit = Trit>,
    {
        assert_eq!(243, inner.size());

        let mut troika = Self::new();
        let n = inner.size();
        for idx in 729 - n..729 {
            troika.set1(idx, inner.get_trit().0);
            inner = inner.drop(1);
        }
        troika
    }

    fn from_inner_trits<TW>(inner: &Tbits<TW>) -> Self
    where
        TW: TritWord, //BasicTbitWord<Tbit = Trit>,
    {
        Self::from_inner(inner.slice())
    }
}

impl Into<Troika> for inner::Inner<Trit, Troika> {
    fn into(self) -> Troika {
        Troika::from_inner_trits(&self.inner)
    }
}

impl From<Troika> for inner::Inner<Trit, Troika> {
    fn from(troika: Troika) -> Self {
        inner::Inner {
            inner: troika.to_inner_trits(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW> PRP<TW> for Troika
where
    TW: TritWord,
{
    /// Rate -- size of outer part of the Spongos state.
    const RATE: usize = 486;

    /// Capacity -- size of inner part of the Spongos state.
    const CAPACITY: usize = 243;

    const MODE: Mode = Mode::OVERWRITE;

    fn transform(&mut self, outer: &mut TbitSliceMut<TW>) {
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
        unsafe {
            outer.pickup_all_mut();
        }

        {
            // move trits from Troika state to outer[0..rate]
            let n = outer.size();
            for idx in 0..n {
                outer.put_trit(Trit(self.get1(idx)));
                outer.advance(1);
            }
        }
    }

    type Inner = inner::Inner<Trit, Troika>;
}
