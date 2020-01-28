use super::{defs::*, util::*, word::*};

impl TritWord for Trit {
    const SIZE: usize = 1;

    fn zero() -> Self {
        0
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

    fn put_trit(d: usize, p: *mut Self, t: Trit) {
        unsafe {
            *(p.add(d)) = t;
        }
    }
    fn get_trit(d: usize, p: *const Self) -> Trit {
        unsafe { *(p.add(d)) }
    }
    fn put_tryte(d: usize, p: *mut Self, t: Tryte) {
        debug_assert!(t < 27);
        let t0 = (t % 3) as Trit;
        let t1 = ((t / 3) % 3) as Trit;
        let t2 = (t / 9) as Trit;
        Trit::put_trit(d + 0, p, t0);
        Trit::put_trit(d + 1, p, t1);
        Trit::put_trit(d + 2, p, t2);
    }
    fn get_tryte(d: usize, p: *const Self) -> Tryte {
        let t0 = Trit::get_trit(d + 0, p) as Tryte;
        let t1 = Trit::get_trit(d + 1, p) as Tryte;
        let t2 = Trit::get_trit(d + 2, p) as Tryte;
        t2 * 9 + t1 * 3 + t0
    }
    fn put1(d: usize, p: *mut Self, t: Trint1) {
        let tt = ((t + 3) % 3) as Trit;
        Self::put_trit(d, p, tt);
    }
    fn get1(d: usize, p: *const Self) -> Trint1 {
        let tt = Self::get_trit(d, p);
        let (r, _) = mods1(tt as i32);
        r
    }
    fn put3(d: usize, p: *mut Self, t: Trint3) {
        let q0 = t as i32;
        let (r0, q1) = mods1(q0);
        Self::put1(d + 0, p, r0);
        let (r1, q2) = mods1(q1);
        Self::put1(d + 1, p, r1);
        let (r2, _) = mods1(q2);
        Self::put1(d + 2, p, r2);
    }
    fn get3(d: usize, p: *const Self) -> Trint3 {
        let t0 = Self::get1(d + 0, p) as Trint3;
        let t1 = Self::get1(d + 1, p) as Trint3;
        let t2 = Self::get1(d + 2, p) as Trint3;
        t0 + 3 * t1 + 9 * t2
    }
    fn put6(d: usize, p: *mut Self, t: Trint6) {
        let q0 = t as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, _) = mods3(q1);
        Self::put3(d + 3, p, r1);
    }
    fn get6(d: usize, p: *const Self) -> Trint6 {
        let t0 = Self::get3(d + 0, p) as Trint6;
        let t1 = Self::get3(d + 3, p) as Trint6;
        t0 + 27 * t1
    }
    fn put9(d: usize, p: *mut Self, t: Trint9) {
        let q0 = t as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, q2) = mods3(q1);
        Self::put3(d + 3, p, r1);
        let (r2, _) = mods3(q2);
        Self::put3(d + 6, p, r2);
    }
    fn get9(d: usize, p: *const Self) -> Trint9 {
        let t0 = Self::get3(d + 0, p) as Trint9;
        let t1 = Self::get3(d + 3, p) as Trint9;
        let t2 = Self::get3(d + 6, p) as Trint9;
        t0 + 27 * t1 + 729 * t2
    }
    fn put18(d: usize, p: *mut Self, t: Trint18) {
        let q0 = t as i32;
        let (r0, q1) = mods9(q0);
        Self::put9(d + 0, p, r0);
        let (r1, _) = mods9(q1);
        Self::put9(d + 9, p, r1);
    }
    fn get18(d: usize, p: *const Self) -> Trint18 {
        let t0 = Self::get9(d + 0, p) as Trint18;
        let t1 = Self::get9(d + 9, p) as Trint18;
        t0 + 19683 * t1
    }

    /// y:=x+s, s:=x, x:=y
    fn unsafe_swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self) {
        unsafe {
            let mut px = x.add(dx);
            let mut ps = s.add(ds);
            for _ in 0..n {
                let ty = (*px + *ps) % 3;
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
                let tx = (3 + *py - *ps) % 3;
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
                let ty = (*px + *ps) % 3;
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
                let tx = (3 + *py - *ps) % 3;
                *ps = tx;
                *px = tx;
                py = py.add(1);
                ps = ps.add(1);
                px = px.add(1);
            }
        }
    }
}
