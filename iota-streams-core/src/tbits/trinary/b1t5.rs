//! 5 trits per 1 byte.

use super::defs::*;
use crate::tbits::word::BasicTbitWord;

/// 5 trits packed into a byte. It represents a "network" trinary word.
///
/// Doesn't implement Eq and Ord as different representations may have the same value (eg. 0 == 243, 1 == 244, 1 > 243, etc.).
#[derive(PartialEq, PartialOrd, Copy, Clone, Debug)]
pub struct B1T5(u8);

impl B1T5 {
    pub fn to_trits(self) -> [Trit; 5] {
        let mut ts: [Trit; 5] = [Trit(0); 5];
        unsafe {
            Self::word_to_tbits(self, ts.as_mut_ptr());
        }
        ts
    }

    pub fn from_trits(ts: &[Trit; 5]) -> Self {
        unsafe { Self::word_from_tbits(ts.as_ptr()) }
    }
}

impl BasicTbitWord for B1T5 {
    type Tbit = Trit;
    const SIZE: usize = 5;
    const ZERO_WORD: B1T5 = B1T5(0);
    const ZERO_TBIT: Trit = Trit(0);

    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit) {
        let mut u = x.0;
        *ts.add(0) = Trit(u % 3);
        u /= 3;
        *ts.add(1) = Trit(u % 3);
        u /= 3;
        *ts.add(2) = Trit(u % 3);
        u /= 3;
        *ts.add(3) = Trit(u % 3);
        u /= 3;
        *ts.add(4) = Trit(u % 3);
    }

    unsafe fn word_from_tbits(ts: *const Self::Tbit) -> Self {
        let mut u = (*ts.add(4)).0;
        u = u * 3 + (*ts.add(3)).0;
        u = u * 3 + (*ts.add(2)).0;
        u = u * 3 + (*ts.add(1)).0;
        u = u * 3 + (*ts.add(0)).0;
        Self(u)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_exhaustive() {
        let num_loops = 2;
        crate::tbits::trinary::word::tests::basic_copy_exhaustive::<B1T5>(num_loops);
    }

    #[test]
    pub fn from_to_trits() {
        for u in 0..243 {
            let b = B1T5(u);
            let b2 = B1T5::from_trits(&b.to_trits());
            assert_eq!(b, b2);
        }
    }
}
