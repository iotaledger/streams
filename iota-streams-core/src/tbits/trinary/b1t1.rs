//! 1 trit per 1 byte.

use super::{
    defs::*,
    word::TritWord,
};
use crate::tbits::word::{
    BasicTbitWord,
    IntTbitWord,
    RngTbitWord,
    SpongosTbitWord,
    StringTbitWord,
};
use std::convert::TryFrom;

impl BasicTbitWord for Trit {
    type Tbit = Trit;
    const SIZE: usize = 1;
    const ZERO_WORD: Trit = Trit(0);
    const ZERO_TBIT: Trit = Trit(0);

    /// Convert word to SIZE tbits.
    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit) {
        *ts = x;
    }

    /// Convert word from SIZE tbits.
    unsafe fn word_from_tbits(ts: *const Self::Tbit) -> Self {
        *ts
    }

    unsafe fn to_tbits(s: usize, dx: usize, x: *const Self, ts: *mut Self::Tbit) {
        std::ptr::copy(x.add(dx), ts, s);
    }

    unsafe fn from_tbits(s: usize, dx: usize, x: *mut Self, ts: *const Self::Tbit) {
        std::ptr::copy(ts, x.add(dx), s);
    }

    unsafe fn copy(s: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        std::ptr::copy(x.add(dx), y.add(dy), s);
    }

    unsafe fn set_zero(s: usize, d: usize, p: *mut Self) {
        std::ptr::write_bytes(p.add(d), 0, s);
    }

    unsafe fn equals(s: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool {
        for i in 0..s {
            if *x.add(dx + i) != *y.add(dy + i) {
                return false;
            }
        }
        true
    }
}

impl StringTbitWord for Trit {
    const TBITS_PER_CHAR: usize = 3;

    unsafe fn put_char(s: usize, mut d: usize, p: *mut Self, c: char) -> bool {
        if let Ok(t) = Trint3::try_from(c) {
            let ts = <[Trint1; 3]>::from(t);

            // Trits are padded with zeros when converted to char.
            for k in std::cmp::min(s, 3)..3 {
                if Trint1(0) != ts[k] {
                    return false;
                }
            }

            for t in &ts[..std::cmp::min(s, 3)] {
                TritWord::put1(d, p, *t);
                d += 1;
            }
            true
        } else {
            false
        }
    }

    unsafe fn get_char(s: usize, mut d: usize, p: *const Self) -> char {
        // Trits are padded with zeros.
        let mut ts: [Trint1; 3] = [Trint1(0); 3];
        for t in &mut ts[..std::cmp::min(s, 3)] {
            *t = TritWord::get1(d, p);
            d += 1;
        }
        char::from(Trint3::from(ts))
    }
}

impl IntTbitWord for Trit {
    unsafe fn put_isize(n: usize, d: usize, p: *mut Self, mut i: isize) {
        <Trit as BasicTbitWord>::unfold_tbits(n, d, p, |x| {
            let r = match i % 3 {
                2 => -1,
                -2 => 1,
                r => r,
            };
            x[0] = Trint1(r as i8).into();
            i = (i - r) / 3;
        });
    }
    unsafe fn get_isize(n: usize, d: usize, p: *const Self) -> isize {
        let mut m = 1_isize;
        let mut i = 0_isize;
        <Trit as BasicTbitWord>::fold_tbits(n, d, p, |x| {
            i += m * (Trint1::from(x[0])).0 as isize;
            m *= 3;
        });
        i
    }
    unsafe fn put_usize(s: usize, d: usize, p: *mut Self, mut u: usize) {
        <Trit as BasicTbitWord>::unfold_tbits(s, d, p, |x| {
            x[0] = Trit((u % 3) as u8);
            u = u / 3;
        });
    }
    unsafe fn get_usize(s: usize, d: usize, p: *const Self) -> usize {
        let mut m = 1_usize;
        let mut u = 0_usize;
        <Trit as BasicTbitWord>::fold_tbits(s, d, p, |x| {
            u += m * x[0].0 as usize;
            m *= 3;
        });
        u
    }
}

impl SpongosTbitWord for Trit {
    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Trit((x.0 + y.0) % 3)
    }

    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Trit((3 + x.0 - y.0) % 3)
    }
}

impl RngTbitWord for Trit {}

impl TritWord for Trit {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbits::*;
    use std::str::FromStr;

    #[test]
    fn copy_exhaustive() {
        let num_loops = 11;
        crate::tbits::trinary::word::tests::basic_copy_exhaustive::<Trit>(num_loops);
    }

    #[test]
    fn add() {
        let a = Tbits::<Trit>::from_str("A").unwrap();
        let b = Tbits::<Trit>::from_str("B").unwrap();
        let ab = Tbits::<Trit>::from_str("AB").unwrap();
        crate::tbits::tests::add(&a, &b, &ab);
    }

    #[test]
    fn get_put_char() {
        let alphabet = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        crate::tbits::tests::get_put_char::<Trit>(alphabet);
    }

    #[test]
    fn get_put_usize() {
        let mut m = 3_usize;
        for n in 1..5 {
            crate::tbits::tests::get_put_usize::<Trit>(n, 0, m - 1);
            m *= 3;
        }
    }

    #[test]
    fn get_put_isize() {
        let mut m = 3_isize;
        for n in 1..5 {
            crate::tbits::tests::get_put_isize::<Trit>(n, -(m - 1) / 2, (m - 1) / 2);
            m *= 3;
        }
    }
}
