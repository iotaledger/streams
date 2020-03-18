//! 1 trit per 1 byte.

use crate::tbits::word::{BasicTbitWord, SpongosTbitWord};
use super::defs::*;
use super::word::TritWord;

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

    unsafe fn to_tbits(n: usize, dx: usize, x: *const Self, ts: *mut Self::Tbit) {
        std::ptr::copy(x.add(dx), ts, n);
    }

    unsafe fn from_tbits(n: usize, dx: usize, x: *mut Self, ts: *const Self::Tbit) {
        std::ptr::copy(ts, x.add(dx), n);
    }

    unsafe fn copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        std::ptr::copy(x.add(dx), y.add(dy), n);
    }

    unsafe fn set_zero(n: usize, d: usize, p: *mut Self) {
        std::ptr::write_bytes(p.add(d), 0, n);
    }

    unsafe fn equals(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool {
        for i in 0..n {
            if *x.add(dx + i) != *y.add(dy + i) {
                return false;
            }
        }
        true
    }
}

impl SpongosTbitWord for Trit {
    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Trit((x.0 + y.0) % 3)
    }

    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit {
        Trit((3 + x.0 - y.0) % 3)
    }

    /// y:=x+s, s:=x, x:=y
    unsafe fn swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self) {
        let mut px = x.add(dx);
        let mut ps = s.add(ds);
        for _ in 0..n {
            let ty = Self::tbit_add(*px, *ps);
            *ps = *px;
            *px = ty;
            px = px.add(1);
            ps = ps.add(1);
        }
    }

    /// x:=y-s, s:=x, y:=x
    unsafe fn swap_sub(n: usize, dy: usize, y: *mut Self, ds: usize, s: *mut Self) {
        let mut py = y.add(dy);
        let mut ps = s.add(ds);
        for _ in 0..n {
            let tx = Self::tbit_sub(*py, *ps);
            *ps = tx;
            *py = tx;
            py = py.add(1);
            ps = ps.add(1);
        }
    }

    /// y:=x+s, s:=x
    unsafe fn copy_add(
        n: usize,
        dx: usize,
        x: *const Self,
        ds: usize,
        s: *mut Self,
        dy: usize,
        y: *mut Self,
    ) {
        let mut px = x.add(dx);
        let mut ps = s.add(ds);
        let mut py = y.add(dy);
        for _ in 0..n {
            let ty = Self::tbit_add(*px, *ps);
            *ps = *px;
            *py = ty;
            px = px.add(1);
            ps = ps.add(1);
            py = py.add(1);
        }
    }

    /// t:=y-s, s:=t, x:=t
    unsafe fn copy_sub(
        n: usize,
        dy: usize,
        y: *const Self,
        ds: usize,
        s: *mut Self,
        dx: usize,
        x: *mut Self,
    ) {
        let mut py = y.add(dy);
        let mut ps = s.add(ds);
        let mut px = x.add(dx);
        for _ in 0..n {
            let tx = Self::tbit_sub(*py, *ps);
            *ps = tx;
            *px = tx;
            py = py.add(1);
            ps = ps.add(1);
            px = px.add(1);
        }
    }
}

impl TritWord for Trit {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive() {
        let num_loops = 11;
        crate::tbits::trinary::word::tests::basic_exhaustive::<Trit>(num_loops);
    }
}
