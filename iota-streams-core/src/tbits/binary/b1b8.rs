//! 8 bits per 1 byte.

use super::defs::*;
use super::word::BitWord;
use crate::tbits::word::{BasicTbitWord, IntTbitWord, SpongosTbitWord, StringTbitWord};

impl BasicTbitWord for Byte {
    type Tbit = Bit;
    const SIZE: usize = 8;
    const ZERO_WORD: Byte = Byte(0);
    const ZERO_TBIT: Bit = Bit(0);

    /// Convert word to SIZE tbits.
    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit) {
        *ts.add(0) = Bit(1 & (x.0 >> 0));
        *ts.add(1) = Bit(1 & (x.0 >> 1));
        *ts.add(2) = Bit(1 & (x.0 >> 2));
        *ts.add(3) = Bit(1 & (x.0 >> 3));
        *ts.add(4) = Bit(1 & (x.0 >> 4));
        *ts.add(5) = Bit(1 & (x.0 >> 5));
        *ts.add(6) = Bit(1 & (x.0 >> 6));
        *ts.add(7) = Bit(1 & (x.0 >> 7));
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

impl StringTbitWord for Byte {
    const TBITS_PER_CHAR: usize = 4;

    unsafe fn put_char(mut s: usize, mut d: usize, mut p: *mut Self, c: char) -> bool {
        let mut b8 = if '0' <= c && c <= '9' {
            c as u8 - b'0'
        } else if 'A' <= c && c <= 'F' {
            c as u8 - b'A' + 10
        } else {
            return false;
        };

        s = std::cmp::min(4, s);
        p = p.add(d / 8);
        d = d % 8;

        let mut mask8 = (1_u8 << s) - 1_u8;

        if s + d <= 8 {
            b8 = b8 << d;
            mask8 = mask8 << d;
            let mut v = *(p as *const u8);
            v = (v & !mask8) | b8;
            *(p as *mut u8) = v;
        } else {
            let b16 = (b8 as u16) << d;
            let mask16 = (mask8 as u16) << d;
            let mut v = *(p as *const u16);
            v = (v & !mask16) | b16;
            *(p as *mut u16) = v;
        }

        true
    }

    unsafe fn get_char(mut s: usize, mut d: usize, mut p: *const Self) -> char {
        s = std::cmp::min(4, s);
        p = p.add(d / 8);
        d = d % 8;

        let mask8 = (1_u8 << s) - 1_u8;

        let b8 = if s + d <= 8 {
            (*(p as *const u8) >> d) & mask8
        } else {
            (*(p as *const u16) >> d) as u8 & mask8
        };

        if b8 < 10 {
            (b'0' + b8) as char
        } else {
            (b'A' - 10 + b8) as char
        }
    }
}

#[test]
fn test_byte_put_char() {
    let mut b = [Byte(0); 1];
    let p: *mut Byte = b.as_mut_ptr();
    unsafe {
        assert_eq!(Byte(0), b[0]);
        assert!(Byte::put_char(8, 0, p, 'B'));
        assert_eq!(Byte(11), b[0]);
        assert!(Byte::put_char(8, 0, p, 'A'));
        assert_eq!(Byte(10), b[0]);
        assert!(Byte::put_char(4, 4, p, 'B'));
        assert_eq!(Byte(10 + (11 << 4)), b[0]);
    }
}

impl IntTbitWord for Byte {
    unsafe fn put_isize(n: usize, d: usize, p: *mut Self, mut i: isize) {
        <Byte as BasicTbitWord>::unfold_tbits(n, d, p, |xs| {
            for x in xs.iter_mut() {
                *x = Bit((i & 1) as u8);
                i = i >> 1;
            }
        });
    }
    unsafe fn get_isize(n: usize, d: usize, p: *const Self) -> isize {
        let mut m = 0_isize;
        let mut i = 0_isize;
        let mut last = 0_isize;
        <Byte as BasicTbitWord>::fold_tbits(n, d, p, |xs| {
            for x in xs.iter() {
                last = ((*x).0 as isize) << m;
                i += last;
                m += 1;
            }
        });
        i = i | !(last - 1);
        i
    }

    unsafe fn put_usize(n: usize, d: usize, mut p: *mut Self, mut u: usize) {
        if n % 8 == 0 && d % 8 == 0 {
            p = p.add(d / 8);
            for _ in 0..n / 8 {
                *p = Byte(u as u8);
                p = p.add(1);
                u = u >> 8;
            }
        } else {
            <Byte as BasicTbitWord>::unfold_tbits(n, d, p, |xs| {
                for x in xs.iter_mut() {
                    *x = Bit((u & 1) as u8);
                    u = u >> 1;
                }
            });
        }
    }
    unsafe fn get_usize(n: usize, d: usize, mut p: *const Self) -> usize {
        let mut u = 0_usize;
        if n % 8 == 0 && d % 8 == 0 {
            p = p.add(d / 8);
            let mut m = 0_usize;
            for _ in 0..n / 8 {
                u |= ((*p).0 as usize) << m;
                p = p.add(1);
                m += 8;
            }
        } else {
            let mut m = 0_usize;
            <Byte as BasicTbitWord>::fold_tbits(n, d, p, |xs| {
                for x in xs.iter() {
                    u += (x.0 as usize) << m;
                    m += 1;
                }
            });
        }
        u
    }
}

impl BitWord for Byte {
    unsafe fn put_byte(d: usize, p: *mut Self, t: Byte) {
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

    unsafe fn get_byte(d: usize, p: *const Self) -> Byte {
        if 0 == d & 7 {
            *p
        } else {
            let pu16 = p.add(d / 8) as *mut u16;
            let b0b1 = *pu16 >> (d & 7);
            Byte(b0b1 as u8)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbits::*;
    use std::str::FromStr;

    #[test]
    fn copy_exhaustive() {
        let num_loops = 2;
        crate::tbits::binary::word::tests::basic_copy_exhaustive::<Byte>(num_loops);
    }

    #[test]
    fn add() {
        let a = Tbits::<Byte>::from_str("A").unwrap();
        let b = Tbits::<Byte>::from_str("B").unwrap();
        let ab = Tbits::<Byte>::from_str("AB").unwrap();
        crate::tbits::tests::add(&a, &b, &ab);
    }

    #[test]
    fn get_put_char() {
        let alphabet = "0123456789ABCDEF";
        crate::tbits::tests::get_put_char::<Byte>(alphabet);
    }

    #[test]
    fn get_put_usize() {
        let mut m = 2_usize;
        for n in 1..17 {
            crate::tbits::tests::get_put_usize::<Byte>(n, 0, m - 1);
            m *= 2;
        }
    }

    #[test]
    fn get_put_isize() {
        let mut m = 2_isize;
        for n in 1..17 {
            crate::tbits::tests::get_put_isize::<Byte>(n, -m / 2, m / 2 - 1);
            m *= 2;
        }
    }
}
