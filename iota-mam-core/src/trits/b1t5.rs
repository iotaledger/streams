use super::{defs::*, word::*};

/// 5 trits packed into a byte. It represents a "network" trinary word.
///
/// Doesn't implement Eq and Ord as different representations may have the same value (eg. 0 == 243, 1 == 244, 1 > 243, etc.).
#[derive(PartialEq, PartialOrd, Copy, Clone, Debug)]
pub struct B1T5(u8);

impl B1T5 {
    fn to_trits(self) -> [Trit; 5] {
        let mut ts: [Trit; 5] = [Trit(0); 5];
        Self::unsafe_word_to_trits(self, ts.as_mut_ptr() as *mut u8);
        ts
    }

    fn from_trits(ts: &[Trit; 5]) -> Self {
        Self::unsafe_word_from_trits(ts.as_ptr() as *const u8)
    }
}

impl BasicTritWord for B1T5 {
    const SIZE: usize = 5;

    fn unsafe_word_to_trits(x: Self, ts: *mut u8) {
        unsafe {
            let mut u = x.0;
            *ts.add(0) = u % 3;
            u /= 3;
            *ts.add(1) = u % 3;
            u /= 3;
            *ts.add(2) = u % 3;
            u /= 3;
            *ts.add(3) = u % 3;
            u /= 3;
            *ts.add(4) = u % 3;
        }
    }
    fn unsafe_word_from_trits(ts: *const u8) -> Self {
        unsafe {
            let mut u = *ts.add(4);
            u = u * 3 + *ts.add(3);
            u = u * 3 + *ts.add(2);
            u = u * 3 + *ts.add(1);
            u = u * 3 + *ts.add(0);
            Self(u)
        }
    }

    fn zero() -> Self {
        Self(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn from_to_trits() {
        for u in 0..243 {
            let b = B1T5(u);
            let b2 = B1T5::from_trits(&b.to_trits());
            assert_eq!(b, b2);
        }
    }

    #[test]
    pub fn basic_exhaustive() {
        crate::trits::word::test::basic_exhaustive::<B1T5>(2);
    }
}
