//use super::{defs::*, word::*};

#[derive(PartialEq, PartialOrd, Copy, Clone, Debug)]
pub struct B8T32(u64);

/*
impl BasicTritWord for B8T32 {
    const SIZE: usize = 32;

    fn unsafe_to_trits(x: Self, ts: *mut u8) {
        unsafe { *ts = x.0 }
    }
    fn unsafe_from_trits(ts: *const u8) -> Self {
        unsafe { Self(*ts) }
    }

    fn zero() -> Self {
        Self(0)
    }
    fn unsafe_copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        unsafe {
            std::ptr::copy(x.add(dx), y.add(dy), n);
        }
    }
    fn unsafe_set_zero(n: usize, d: usize, p: *mut Self) {
        unsafe {
            std::ptr::write_bytes(p.add(d), 0, n);
        }
    }
    fn unsafe_eq(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool {
        unsafe {
            for i in 0..n {
                if *x.add(dx + i) != *y.add(dy + i) {
                    return false;
                }
            }
        }
        true
    }
}

impl TritWord for B8T32 {
    fn put_trit(d: usize, p: *mut Self, t: Trit) {
        unsafe {
            *(p.add(d)) = t;
        }
    }
    fn get_trit(d: usize, p: *const Self) -> Trit {
        unsafe { *(p.add(d)) }
    }

    /// y:=x+s, s:=x, x:=y
    fn unsafe_swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self) {
        unsafe {
            let mut px = x.add(dx);
            let mut ps = s.add(ds);
            for _ in 0..n {
                let ty = Self(((*px).0 + (*ps).0) % 3);
                *ps = *px;
                *px = ty;
                px = px.add(1);
                ps = ps.add(1);
            }
        }
    }
    /// x:=y-s, s:=x, y:=x
    fn unsafe_swap_sub(n: usize, dy: usize, y: *mut Self, ds: usize, s: *mut Self) {
        unsafe {
            let mut py = y.add(dy);
            let mut ps = s.add(ds);
            for _ in 0..n {
                let tx = Self((3 + (*py).0 - (*ps).0) % 3);
                *ps = tx;
                *py = tx;
                py = py.add(1);
                ps = ps.add(1);
            }
        }
    }
    /// y:=x+s, s:=x
    fn unsafe_copy_add(
        n: usize,
        dx: usize,
        x: *const Self,
        ds: usize,
        s: *mut Self,
        dy: usize,
        y: *mut Self,
    ) {
        unsafe {
            let mut px = x.add(dx);
            let mut ps = s.add(ds);
            let mut py = y.add(dy);
            for _ in 0..n {
                let ty = Self(((*px).0 + (*ps).0) % 3);
                *ps = *px;
                *py = ty;
                px = px.add(1);
                ps = ps.add(1);
                py = py.add(1);
            }
        }
    }
    /// t:=y-s, s:=t, x:=t
    fn unsafe_copy_sub(
        n: usize,
        dy: usize,
        y: *const Self,
        ds: usize,
        s: *mut Self,
        dx: usize,
        x: *mut Self,
    ) {
        unsafe {
            let mut py = y.add(dy);
            let mut ps = s.add(ds);
            let mut px = x.add(dx);
            for _ in 0..n {
                let tx = Self((3 + (*py).0 - (*ps).0) % 3);
                *ps = tx;
                *px = tx;
                py = py.add(1);
                ps = ps.add(1);
                px = px.add(1);
            }
        }
    }
}
 */
