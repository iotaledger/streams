use super::{defs::*, util::*};

/// Abstraction for a trinary word containing one or several trits.
/// The size and encoding of trinary word is defined by the implementation.
/// Many functions take a pair `(d,p)` encoding a slice of trits as input where
/// `d` is the current trit offset, `p` is the raw pointer to the first word in a slice.
pub trait BasicTritWord: Sized + Copy + PartialEq {
    /// The number of trits per word.
    const SIZE: usize;

    /// Convert word to SIZE trits.
    fn unsafe_word_to_trits(x: Self, ts: *mut u8);
    /// Convert word from SIZE trits.
    fn unsafe_word_from_trits(ts: *const u8) -> Self;
    /// All-zero trits word.
    fn zero() -> Self;

    fn unsafe_fold_trits<F>(n: usize, dx: usize, x: *const Self, mut f: F)
    where
        F: FnMut(&[Trit]),
    {
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![Trit(0u8); Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&v[rx..rx + d]);
                nn -= d;
                xx = xx.add(1);
            }

            d = Self::SIZE;
            while nn >= d {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&v[..]);
                nn -= d;
                xx = xx.add(1);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&v[..nn]);
            }
        }
    }

    fn unsafe_refold_trits<F>(n: usize, dx: usize, x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Trit]),
    {
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![Trit(0u8); Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&mut v[rx..rx + d]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
                nn -= d;
                xx = xx.add(1);
            }

            d = Self::SIZE;
            while nn >= d {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&mut v[..]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
                nn -= d;
                xx = xx.add(1);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&mut v[..nn]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
            }
        }
    }

    fn unsafe_unfold_trits<F>(n: usize, dx: usize, x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Trit]),
    {
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![Trit(0u8); Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&mut v[rx..rx + d]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
                nn -= d;
                xx = xx.add(1);
            }

            d = Self::SIZE;
            while nn >= d {
                f(&mut v[..]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
                nn -= d;
                xx = xx.add(1);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr() as *mut u8);
                f(&mut v[..nn]);
                *xx = Self::unsafe_word_from_trits(v.as_ptr() as *const u8);
            }
        }
    }

    fn unsafe_to_trits(n: usize, dx: usize, x: *const Self, mut ts: *mut u8) {
        Self::unsafe_fold_trits(n, dx, x, |tx| unsafe {
            std::ptr::copy(tx.as_ptr(), ts as *mut Trit, tx.len());
            ts = ts.add(tx.len());
        });
        /*
         */
        /*
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![0u8; Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut tt = ts;
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                std::ptr::copy(v.as_mut_ptr().add(rx), tt, d);
                nn -= d;
                xx = xx.add(1);
                tt = tt.add(d);
            }

            d = Self::SIZE;
            while nn >= d {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                std::ptr::copy(v.as_mut_ptr(), tt, d);
                nn -= d;
                xx = xx.add(1);
                tt = tt.add(d);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                std::ptr::copy(v.as_mut_ptr(), tt, nn);
            }
        }
         */
    }

    fn unsafe_from_trits(n: usize, dx: usize, x: *mut Self, mut ts: *const u8) {
        /*
         */
        Self::unsafe_unfold_trits(n, dx, x, |tx| unsafe {
            //TODO: This cast here `ts as *const Trit` is unsafe, need to convert to 0..2.
            println!("tx in ={:?}", tx);
            std::ptr::copy(ts as *const Trit, tx.as_mut_ptr(), tx.len());
            println!("tx out={:?}", tx);
            ts = ts.add(tx.len());
        });
        /*
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![0u8; Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut tt = ts;
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                std::ptr::copy(tt, v.as_mut_ptr().add(rx), d);
                *xx = Self::unsafe_word_from_trits(v.as_ptr());
                nn -= d;
                xx = xx.add(1);
                tt = tt.add(d);
            }

            d = Self::SIZE;
            while nn >= d {
                std::ptr::copy(tt, v.as_mut_ptr(), d);
                *xx = Self::unsafe_word_from_trits(v.as_ptr());
                nn -= d;
                xx = xx.add(1);
                tt = tt.add(d);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                for i in 0..nn {
                    debug_assert!(*tt.add(i) < 3);
                }
                std::ptr::copy(tt, v.as_mut_ptr(), nn);
                *xx = Self::unsafe_word_from_trits(v.as_ptr());
            }
        }
         */
    }

    /// Copy `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        if n == 0 {
            return;
        }

        unsafe {
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let ry = dy % Self::SIZE;
            let mut yy = y.add(dy / Self::SIZE);
            let mut nn = n;

            if rx == ry {
                let mut xs = vec![0u8; Self::SIZE];
                let mut ys = vec![0u8; Self::SIZE];

                if rx != 0 {
                    Self::unsafe_word_to_trits(*xx, xs.as_mut_ptr());
                    Self::unsafe_word_to_trits(*yy, ys.as_mut_ptr());
                    let d = std::cmp::min(n, Self::SIZE - rx);
                    ys[ry..ry + d].copy_from_slice(&xs[rx..rx + d]);
                    *yy = Self::unsafe_word_from_trits(ys.as_ptr());

                    nn -= d;
                    xx = xx.add(1);
                    yy = yy.add(1);
                }

                std::ptr::copy(xx, yy, nn / Self::SIZE);

                xx = xx.add(nn / Self::SIZE);
                yy = yy.add(nn / Self::SIZE);
                nn = nn % Self::SIZE;

                if nn != 0 {
                    Self::unsafe_word_to_trits(*xx, xs.as_mut_ptr());
                    Self::unsafe_word_to_trits(*yy, ys.as_mut_ptr());
                    ys[0..nn].copy_from_slice(&xs[0..nn]);
                    *yy = Self::unsafe_word_from_trits(ys.as_ptr());
                }
            } else {
                // Rare case, just convert via trits.
                let mut ts = vec![0u8; n];
                Self::unsafe_to_trits(n, dx, x, ts.as_mut_ptr());
                Self::unsafe_from_trits(n, dy, y, ts.as_ptr());
            }
        }
    }
    /// Set `n` trits in `(dx,x)` slice to zero.
    fn unsafe_set_zero(n: usize, dx: usize, x: *mut Self) {
        if n == 0 {
            return;
        }

        unsafe {
            let mut v = vec![0u8; Self::SIZE];
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let mut nn = n;
            let mut d;

            if rx != 0 {
                d = std::cmp::min(n, Self::SIZE - rx);
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                for i in rx..rx + d {
                    *v.as_mut_ptr().add(i) = 0;
                }
                *xx = Self::unsafe_word_from_trits(v.as_ptr());
                nn -= d;
                xx = xx.add(1);
            }

            d = Self::SIZE;
            while nn >= d {
                *xx = Self::zero();
                nn -= d;
                xx = xx.add(1);
            }

            if nn > 0 {
                Self::unsafe_word_to_trits(*xx, v.as_mut_ptr());
                for i in 0..nn {
                    *v.as_mut_ptr().add(i) = 0;
                }
                *xx = Self::unsafe_word_from_trits(v.as_ptr());
            }
        }
    }
    /// Compare `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_eq(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool {
        if n == 0 {
            return true;
        }

        unsafe {
            let rx = dx % Self::SIZE;
            let mut xx = x.add(dx / Self::SIZE);
            let ry = dy % Self::SIZE;
            let mut yy = y.add(dy / Self::SIZE);
            let mut nn = n;

            if rx == ry {
                let mut xs = vec![0u8; Self::SIZE];
                let mut ys = vec![0u8; Self::SIZE];

                if rx != 0 {
                    Self::unsafe_word_to_trits(*xx, xs.as_mut_ptr());
                    Self::unsafe_word_to_trits(*yy, ys.as_mut_ptr());
                    let d = std::cmp::min(n, Self::SIZE - rx);
                    if ys[ry..ry + d] != xs[rx..rx + d] {
                        return false;
                    }

                    nn -= d;
                    xx = xx.add(1);
                    yy = yy.add(1);
                }

                while nn >= Self::SIZE {
                    if *xx != *yy {
                        return false;
                    }
                    nn -= Self::SIZE;
                    xx = xx.add(1);
                    yy = yy.add(1);
                }

                xx = xx.add(nn / Self::SIZE);
                yy = yy.add(nn / Self::SIZE);
                nn = nn % Self::SIZE;

                if nn != 0 {
                    Self::unsafe_word_to_trits(*xx, xs.as_mut_ptr());
                    Self::unsafe_word_to_trits(*yy, ys.as_mut_ptr());
                    if ys[0..nn] != xs[0..nn] {
                        return false;
                    }
                }

                true
            } else {
                // Rare case, just convert via trits.
                let mut xs = vec![0u8; n];
                let mut ys = vec![0u8; n];
                Self::unsafe_to_trits(n, dx, x, xs.as_mut_ptr());
                Self::unsafe_to_trits(n, dy, y, ys.as_mut_ptr());
                xs == ys
            }
        }
    }
}

/// Representations supporting efficient integer conversions and spongos operations.
pub trait TritWord: BasicTritWord {
    // Integer conversion utils

    fn put_trit(d: usize, p: *mut Self, t: Trit) {
        unsafe {
            let mut ts = vec![Trit(0); Self::SIZE];
            Self::unsafe_word_to_trits(*p.add(d / Self::SIZE), ts.as_mut_ptr() as *mut u8);
            ts[d % Self::SIZE] = t;
            *p.add(d / Self::SIZE) = Self::unsafe_word_from_trits(ts.as_ptr() as *const u8);
        }
    }
    fn get_trit(d: usize, p: *const Self) -> Trit {
        unsafe {
            let mut ts = vec![Trit(0); Self::SIZE];
            Self::unsafe_word_to_trits(*p.add(d / Self::SIZE), ts.as_mut_ptr() as *mut u8);
            ts[d % Self::SIZE]
        }
    }

    fn put_tryte(d: usize, p: *mut Self, t: Tryte) {
        debug_assert!(t.0 < 27);
        let mut u = t.0;
        let t0 = Trit(u % 3);
        u /= 3;
        let t1 = Trit(u % 3);
        u /= 3;
        let t2 = Trit(u % 3);
        Self::put_trit(d + 0, p, t0);
        Self::put_trit(d + 1, p, t1);
        Self::put_trit(d + 2, p, t2);
    }
    fn get_tryte(d: usize, p: *const Self) -> Tryte {
        let mut u = Self::get_trit(d + 2, p).0;
        u = u * 3 + Self::get_trit(d + 1, p).0;
        u = u * 3 + Self::get_trit(d + 0, p).0;
        Tryte(u)
    }
    fn put1(d: usize, p: *mut Self, t: Trint1) {
        let tt = Trit(((t.0 + 3) % 3) as u8);
        Self::put_trit(d, p, tt);
    }
    fn get1(d: usize, p: *const Self) -> Trint1 {
        let tt = Self::get_trit(d, p);
        let (r, _) = mods1(tt.0 as i32);
        r
    }
    fn put3(d: usize, p: *mut Self, t: Trint3) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods1(q0);
        Self::put1(d + 0, p, r0);
        let (r1, q2) = mods1(q1);
        Self::put1(d + 1, p, r1);
        let (r2, _) = mods1(q2);
        Self::put1(d + 2, p, r2);
    }
    fn get3(d: usize, p: *const Self) -> Trint3 {
        let t0 = Self::get1(d + 0, p).0 as i8;
        let t1 = Self::get1(d + 1, p).0 as i8;
        let t2 = Self::get1(d + 2, p).0 as i8;
        Trint3(t0 + 3 * t1 + 9 * t2)
    }
    fn put6(d: usize, p: *mut Self, t: Trint6) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, _) = mods3(q1);
        Self::put3(d + 3, p, r1);
    }
    fn get6(d: usize, p: *const Self) -> Trint6 {
        let t0 = Self::get3(d + 0, p).0 as i16;
        let t1 = Self::get3(d + 3, p).0 as i16;
        Trint6(t0 + 27 * t1)
    }
    fn put9(d: usize, p: *mut Self, t: Trint9) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods3(q0);
        Self::put3(d + 0, p, r0);
        let (r1, q2) = mods3(q1);
        Self::put3(d + 3, p, r1);
        let (r2, _) = mods3(q2);
        Self::put3(d + 6, p, r2);
    }
    fn get9(d: usize, p: *const Self) -> Trint9 {
        let t0 = Self::get3(d + 0, p).0 as i16;
        let t1 = Self::get3(d + 3, p).0 as i16;
        let t2 = Self::get3(d + 6, p).0 as i16;
        Trint9(t0 + 27 * t1 + 729 * t2)
    }
    fn put18(d: usize, p: *mut Self, t: Trint18) {
        let q0 = t.0 as i32;
        let (r0, q1) = mods9(q0);
        Self::put9(d + 0, p, r0);
        let (r1, _) = mods9(q1);
        Self::put9(d + 9, p, r1);
    }
    fn get18(d: usize, p: *const Self) -> Trint18 {
        let t0 = Self::get9(d + 0, p).0 as i32;
        let t1 = Self::get9(d + 9, p).0 as i32;
        Trint18(t0 + 19683 * t1)
    }

    // Spongos-related utils

    /// y:=x+s, s:=x, x:=y
    fn unsafe_swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self);
    /// x:=y-s, s:=x, y:=x
    fn unsafe_swap_sub(n: usize, dy: usize, y: *mut Self, ds: usize, s: *mut Self);
    /// y:=x+s, s:=x
    fn unsafe_copy_add(
        n: usize,
        dx: usize,
        x: *const Self,
        ds: usize,
        s: *mut Self,
        dy: usize,
        y: *mut Self,
    );
    /// t:=y-s, s:=t, x:=t
    fn unsafe_copy_sub(
        n: usize,
        dy: usize,
        y: *const Self,
        ds: usize,
        s: *mut Self,
        dx: usize,
        x: *mut Self,
    );
}

//#[cfg(test)]
pub mod test {
    use super::*;
    use crate::trits::{TritSliceT, TritsT};
    use std::num::Wrapping;

    pub fn copy_range_trits<TW: BasicTritWord>(m: usize, n: usize, ts: &[Trit]) {
        println!("copy_range_trits m={} n={} ts={:?}", m, n, ts);
        let t0 = TritsT::<TW>::from_trits(&ts[..m]);
        let t1 = TritsT::<TW>::from_trits(&ts[m..n]);
        let t2 = TritsT::<TW>::from_trits(&ts[n..]);
        let t012 = TritsT::<TW>::from_trits(&ts);

        let to_trits = |t: TritSliceT<TW>| {
            let mut v = vec![Trit(0); t.size()];
            t.get_trits(&mut v[..]);
            v
        };

        let mut x0 = TritsT::<TW>::zero(ts.len());
        x0.slice_mut().put_trits(ts);
        assert_eq!(t012, x0);
        assert_eq!(ts, &to_trits(x0.slice())[..]);

        let mut x1 = TritsT::<TW>::zero(ts.len());
        println!("x1 = {:?}", x1);
        x1.slice_mut().take(m).put_trits(&ts[..m]);
        println!("x1 = {:?}", x1);
        x1.slice_mut().drop(m).take(n - m).put_trits(&ts[m..n]);
        println!("x1 = {:?}", x1);
        x1.slice_mut().drop(n).put_trits(&ts[n..]);
        println!("x1 = {:?}", x1);
        assert_eq!(t012, x1);
        assert_eq!(ts, &to_trits(x1.slice())[..]);

        let mut x2 = TritsT::<TW>::zero(ts.len());
        x2.slice_mut().drop(n).put_trits(&ts[n..]);
        x2.slice_mut().take(m).put_trits(&ts[..m]);
        x2.slice_mut().drop(m).take(n - m).put_trits(&ts[m..n]);
        assert_eq!(t012, x2);
        assert_eq!(t0.slice(), x2.slice().take(m));
        assert_eq!(t1.slice(), x2.slice().drop(m).take(n - m));
        assert_eq!(t2.slice(), x2.slice().drop(n));
        assert_eq!(ts, &to_trits(x2.slice())[..]);
        assert_eq!(ts[..m], to_trits(x2.slice().take(m))[..]);
        assert_eq!(ts[m..n], to_trits(x2.slice().drop(m).take(n - m))[..]);
        assert_eq!(ts[n..], to_trits(x2.slice().drop(n))[..]);
        x2.slice_mut().set_zero();
        x2.slice_mut().drop(m).take(n - m).put_trits(&ts[m..n]);
        x2.slice_mut().drop(n).put_trits(&ts[n..]);
        x2.slice_mut().take(m).put_trits(&ts[..m]);
        assert_eq!(t012, x2);
        x2.slice_mut().take(m).set_zero();
        x2.slice_mut().take(m).put_trits(&ts[..m]);
        x2.slice_mut().drop(m).take(n - m).set_zero();
        x2.slice_mut().drop(m).take(n - m).put_trits(&ts[m..n]);
        x2.slice_mut().drop(n).set_zero();
        x2.slice_mut().drop(n).put_trits(&ts[n..]);
        assert_eq!(t012, x2);
        x2.slice_mut().drop(m).take(n - m).set_zero();
        x2.slice_mut().drop(m).take(n - m).put_trits(&ts[m..n]);
        x2.slice_mut().drop(n).set_zero();
        x2.slice_mut().drop(n).put_trits(&ts[n..]);
        x2.slice_mut().take(m).set_zero();
        x2.slice_mut().take(m).put_trits(&ts[..m]);
        assert_eq!(t012, x2);

        let mut x3 = TritsT::<TW>::zero(ts.len());
        t0.slice().copy(x3.slice_mut().take(m));
        t1.slice().copy(x3.slice_mut().drop(m).take(n - m));
        t2.slice().copy(x3.slice_mut().drop(n));
        assert_eq!(t012, x3);
        assert_eq!(ts, &to_trits(x3.slice())[..]);

        let mut x4 = TritsT::<TW>::zero(ts.len());
        t2.slice().copy(x4.slice_mut().drop(n));
        t0.slice().copy(x4.slice_mut().take(m));
        t1.slice().copy(x4.slice_mut().drop(m).take(n - m));
        assert_eq!(t012, x4);
        assert_eq!(ts, &to_trits(x4.slice())[..]);

        x4.slice_mut().set_zero();
        t1.slice().copy(x4.slice_mut().drop(m).take(n - m));
        t2.slice().copy(x4.slice_mut().drop(n));
        t0.slice().copy(x4.slice_mut().take(m));
        assert_eq!(t012, x4);
        x4.slice_mut().take(m).set_zero();
        t0.slice().copy(x4.slice_mut().take(m));
        x4.slice_mut().drop(m).take(n - m).set_zero();
        t1.slice().copy(x4.slice_mut().drop(m).take(n - m));
        x4.slice_mut().drop(n).set_zero();
        t2.slice().copy(x4.slice_mut().drop(n));
        assert_eq!(t012, x4);
        x4.slice_mut().drop(m).take(n - m).set_zero();
        t1.slice().copy(x4.slice_mut().drop(m).take(n - m));
        x4.slice_mut().drop(n).set_zero();
        t2.slice().copy(x4.slice_mut().drop(n));
        x4.slice_mut().take(m).set_zero();
        t0.slice().copy(x4.slice_mut().take(m));
        assert_eq!(t012, x4);
        assert_eq!(t0.slice(), x4.slice().take(m));
        assert_eq!(t1.slice(), x4.slice().drop(m).take(n - m));
        assert_eq!(t2.slice(), x4.slice().drop(n));
        assert_eq!(ts, &to_trits(x4.slice())[..]);
        assert_eq!(ts[..m], to_trits(x4.slice().take(m))[..]);
        assert_eq!(ts[m..n], to_trits(x4.slice().drop(m).take(n - m))[..]);
        assert_eq!(ts[n..], to_trits(x4.slice().drop(n))[..]);
    }
    fn copy_trits<TW: BasicTritWord>(ts: &[Trit]) {
        let s = ts.len();
        for m in 0..(s / 7 * 2 + 1) {
            for n in m..(s / 7 * 5 + 1) {
                for r in n..s {
                    copy_range_trits::<TW>(m, n, &ts[..r]);
                }
            }
        }
    }

    pub fn basic_exhaustive<TW: BasicTritWord>(num_loops: usize) {
        let s = TW::SIZE * 7;
        let mut ts = vec![Trit(0); s];

        /*
        copy_trits::<TW>(&ts);
        ts.iter_mut().map(|v| *v = Trit(1));
        copy_trits::<TW>(&ts);
        ts.iter_mut().map(|v| *v = Trit(2));
        copy_trits::<TW>(&ts);
         */

        let mut u = Wrapping(11u8);
        for _ in 0..num_loops {
            for v in ts.iter_mut() {
                u = u * Wrapping(7) + Wrapping(0xcd);
                *v = Trit((u.0 ^ 0xaa) % 3)
            }
            copy_trits::<TW>(&ts);
        }
    }
}
