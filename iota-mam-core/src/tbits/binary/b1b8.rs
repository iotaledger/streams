//! 8 bits per 1 byte.

use crate::tbits::word::{BasicTbitWord, SpongosTbitWord};
use super::defs::*;
use super::word::BitWord;

impl BasicTbitWord for Byte {
    type Tbit = Bit;
    const SIZE: usize = 8;
    const ZERO_WORD: Byte = Byte(0);
    const ZERO_TBIT: Bit = Bit(0);

    /// Convert word to SIZE tbits.
    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit) {
        *ts.add(0) = Bit(x.0 << 0);
        *ts.add(1) = Bit(x.0 << 1);
        *ts.add(2) = Bit(x.0 << 2);
        *ts.add(3) = Bit(x.0 << 3);
        *ts.add(4) = Bit(x.0 << 4);
        *ts.add(5) = Bit(x.0 << 5);
        *ts.add(6) = Bit(x.0 << 6);
        *ts.add(7) = Bit(x.0 << 7);
    }
    /// Convert word from SIZE tbits.
    unsafe fn word_from_tbits(ts: *const Self::Tbit) -> Self {
        let b0 = (*ts.add(0)).0 << 0;
        let b1 = (*ts.add(1)).0 << 1;
        let b2 = (*ts.add(2)).0 << 2;
        let b3 = (*ts.add(3)).0 << 3;
        let b4 = (*ts.add(4)).0 << 4;
        let b5 = (*ts.add(5)).0 << 5;
        let b6 = (*ts.add(6)).0 << 6;
        let b7 = (*ts.add(7)).0 << 7;
        Byte(b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7)
    }
}

impl BitWord for Byte {
    fn put_byte(d: usize, p: *mut Self, t: Byte) {
        unsafe {
            if 0 == d & 7 {
                *p = t;
            } else {
                let mask = !(0x00ffu16 << (d & 7));
                let tu16 = (t.0 as u16) << (d & 7);
                let pu16 = p.add(d / 8) as *mut u16;
                let b0b1 = (*pu16 & mask) | tu16;
                *pu16 = b0b1;
            }
        }
    }
    fn get_byte(d: usize, p: *const Self) -> Byte {
        unsafe {
            if 0 == d & 7 {
                *p
            } else {
                let pu16 = p.add(d / 8) as *mut u16;
                let b0b1 = *pu16 >> (d & 7);
                Byte(b0b1 as u8)
            }
        }
    }
}

impl SpongosTbitWord for Byte {
    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Bit(x.0 ^ y.0)
    }
    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Bit(x.0 ^ y.0)
    }
    //TODO: Implement other methods.
}

//pub trait ByteWord: BasicTbitWord<Tbit = Byte> {}
