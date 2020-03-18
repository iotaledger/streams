//! 1 bit per 1 byte.

use crate::tbits::word::{BasicTbitWord, SpongosTbitWord};
use super::defs::*;
use super::word::BitWord;

impl BasicTbitWord for Bit {
    type Tbit = Bit;
    const SIZE: usize = 8;
    const ZERO_WORD: Bit = Bit(0);
    const ZERO_TBIT: Bit = Bit(0);

    /// Convert word to SIZE tbits.
    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit) {
        *ts.add(0) = x;
    }
    /// Convert word from SIZE tbits.
    unsafe fn word_from_tbits(ts: *const Self::Tbit) -> Self {
        *ts.add(0)
    }
}

impl BitWord for Bit {}

impl SpongosTbitWord for Bit {
    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Bit(x.0 ^ y.0)
    }
    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Bit(x.0 ^ y.0)
    }
    //TODO: Implement other methods.
}

//pub trait ByteWord: BasicTbitWord<Tbit = Byte> {}

