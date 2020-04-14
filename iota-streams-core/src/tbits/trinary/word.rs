use super::{
    defs::*,
    util::*,
};
use crate::tbits::word::BasicTbitWord;

/// Representations supporting efficient integer conversions and spongos operations.
pub trait TritWord: BasicTbitWord<Tbit = Trit> {
    // Integer conversion utils

    unsafe fn put_tryte(d: usize, p: *mut Self, t: Tryte) {
        debug_assert!(t.0 < 27);
        let mut u = t.0;
        let t0 = Trit(u % 3);
        u /= 3;
        let t1 = Trit(u % 3);
        u /= 3;
        let t2 = Trit(u % 3);
        Self::put_tbit(d + 0, p, t0);
        Self::put_tbit(d + 1, p, t1);
        Self::put_tbit(d + 2, p, t2);
    }
    unsafe fn get_tryte(d: usize, p: *const Self) -> Tryte {
        let mut u = Self::get_tbit(d + 2, p).0;
        u = u * 3 + Self::get_tbit(d + 1, p).0;
        u = u * 3 + Self::get_tbit(d + 0, p).0;
        Tryte(u)
    }

    unsafe fn put1(d: usize, p: *mut Self, t: Trint1) {
        let tt = Trit(((t.0 + 3) % 3) as u8);
        Self::put_tbit(d, p, tt);
    }
    unsafe fn get1(d: usize, p: *const Self) -> Trint1 {
        let tt = Self::get_tbit(d, p);
        let (r, _) = mods1(tt.0 as i32);
        r
    }

    unsafe fn put3(d: usize, p: *mut Self, t: Trint3) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods1(q0);
        Self::put1(d + 0, p, r0);
        let (r1, q2) = mods1(q1);
        Self::put1(d + 1, p, r1);
        let (r2, _) = mods1(q2);
        Self::put1(d + 2, p, r2);
    }
    unsafe fn get3(d: usize, p: *const Self) -> Trint3 {
        let t0 = Self::get1(d + 0, p).0 as i8;
        let t1 = Self::get1(d + 1, p).0 as i8;
        let t2 = Self::get1(d + 2, p).0 as i8;
        Trint3(t0 + 3 * t1 + 9 * t2)
    }

    unsafe fn put6(d: usize, p: *mut Self, t: Trint6) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, _) = mods3(q1);
        Self::put3(d + 3, p, r1);
    }
    unsafe fn get6(d: usize, p: *const Self) -> Trint6 {
        let t0 = Self::get3(d + 0, p).0 as i16;
        let t1 = Self::get3(d + 3, p).0 as i16;
        Trint6(t0 + 27 * t1)
    }

    unsafe fn put9(d: usize, p: *mut Self, t: Trint9) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, q2) = mods3(q1);
        Self::put3(d + 3, p, r1);
        let (r2, _) = mods3(q2);
        Self::put3(d + 6, p, r2);
    }
    unsafe fn get9(d: usize, p: *const Self) -> Trint9 {
        let t0 = Self::get3(d + 0, p).0 as i16;
        let t1 = Self::get3(d + 3, p).0 as i16;
        let t2 = Self::get3(d + 6, p).0 as i16;
        Trint9(t0 + 27 * t1 + 729 * t2)
    }

    unsafe fn put18(d: usize, p: *mut Self, t: Trint18) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods9(q0);
        Self::put9(d + 0, p, r0);
        let (r1, _) = mods9(q1);
        Self::put9(d + 9, p, r1);
    }
    unsafe fn get18(d: usize, p: *const Self) -> Trint18 {
        let t0 = Self::get9(d + 0, p).0 as i32;
        let t1 = Self::get9(d + 9, p).0 as i32;
        Trint18(t0 + 19683 * t1)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //use std::fmt;
    use super::*;
    use crate::tbits::tests::*;
    use std::num::Wrapping;

    pub fn basic_copy_exhaustive<TW>(num_loops: usize)
    where
        TW: BasicTbitWord<Tbit = Trit>,
        //TW::Tbit: fmt::Display + fmt::Debug,
    {
        let s = TW::SIZE * 7;
        let mut ts = vec![TW::ZERO_TBIT; s];

        copy_tbits::<TW>(&ts);
        ts.iter_mut().for_each(|v| *v = Trit(1));
        copy_tbits::<TW>(&ts);
        ts.iter_mut().for_each(|v| *v = Trit(2));
        copy_tbits::<TW>(&ts);

        let mut u = Wrapping(11u8);
        for _ in 0..num_loops {
            for v in ts.iter_mut() {
                u = u * Wrapping(7) + Wrapping(0xcd);
                *v = Trit((u.0 ^ 0xaa) % 3)
            }
            copy_tbits::<TW>(&ts);
        }
    }
}
