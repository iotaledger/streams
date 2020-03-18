/// Abstraction for a binary/trinary word containing one or several tbits (bits/trits).
/// The size and encoding of the word is defined by the implementation.
/// Many functions take a pair `(d,p)` encoding a slice of tbits as input where
/// `d` is the current tbit offset, `p` is the raw pointer to the first word in a slice.
pub trait BasicTbitWord: Sized + Copy + PartialEq {
    /// The number of trits per word.
    const SIZE: usize;
    /// Trit or bit.
    type Tbit: Sized + Copy + PartialEq;

    /// Zero tbit.
    const ZERO_TBIT: Self::Tbit;
    /// All-zero tbits word.
    const ZERO_WORD: Self;

    /// Convert word to SIZE tbits.
    unsafe fn word_to_tbits(x: Self, ts: *mut Self::Tbit);
    /// Convert word from SIZE tbits.
    unsafe fn word_from_tbits(ts: *const Self::Tbit) -> Self;

    unsafe fn put_tbit(d: usize, p: *mut Self, t: Self::Tbit) {
        let mut ts = vec![Self::ZERO_TBIT; Self::SIZE];
        Self::word_to_tbits(*p.add(d / Self::SIZE), ts.as_mut_ptr());
        ts[d % Self::SIZE] = t;
        *p.add(d / Self::SIZE) = Self::word_from_tbits(ts.as_ptr());
    }
    unsafe fn get_tbit(d: usize, p: *const Self) -> Self::Tbit {
        let mut ts = vec![Self::ZERO_TBIT; Self::SIZE];
        Self::word_to_tbits(*p.add(d / Self::SIZE), ts.as_mut_ptr());
        ts[d % Self::SIZE]
    }

    unsafe fn fold_tbits<F>(n: usize, dx: usize, x: *const Self, mut f: F)
    where
        F: FnMut(&[Self::Tbit]),
    {
        if n == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let mut nn = n;
        let mut d;

        if rx != 0 {
            d = std::cmp::min(n, Self::SIZE - rx);
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&v[rx..rx + d]);
            nn -= d;
            xx = xx.add(1);
        }

        d = Self::SIZE;
        while nn >= d {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&v[..]);
            nn -= d;
            xx = xx.add(1);
        }

        if nn > 0 {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&v[..nn]);
        }
    }

    unsafe fn refold_tbits<F>(n: usize, dx: usize, x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Self::Tbit]),
    {
        if n == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let mut nn = n;
        let mut d;

        if rx != 0 {
            d = std::cmp::min(n, Self::SIZE - rx);
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&mut v[rx..rx + d]);
            *xx = Self::word_from_tbits(v.as_ptr());
            nn -= d;
            xx = xx.add(1);
        }

        d = Self::SIZE;
        while nn >= d {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&mut v[..]);
            *xx = Self::word_from_tbits(v.as_ptr());
            nn -= d;
            xx = xx.add(1);
        }

        if nn > 0 {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&mut v[..nn]);
            *xx = Self::word_from_tbits(v.as_ptr());
        }
    }

    unsafe fn unfold_tbits<F>(n: usize, dx: usize, x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Self::Tbit]),
    {
        if n == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let mut nn = n;
        let mut d;

        if rx != 0 {
            d = std::cmp::min(n, Self::SIZE - rx);
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&mut v[rx..rx + d]);
            *xx = Self::word_from_tbits(v.as_ptr());
            nn -= d;
            xx = xx.add(1);
        }

        d = Self::SIZE;
        while nn >= d {
            f(&mut v[..]);
            *xx = Self::word_from_tbits(v.as_ptr());
            nn -= d;
            xx = xx.add(1);
        }

        if nn > 0 {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            f(&mut v[..nn]);
            *xx = Self::word_from_tbits(v.as_ptr());
        }
    }

    unsafe fn to_tbits(n: usize, dx: usize, x: *const Self, mut ts: *mut Self::Tbit) {
        Self::fold_tbits(n, dx, x, |tx| {
            std::ptr::copy(tx.as_ptr(), ts, tx.len());
            ts = ts.add(tx.len());
        });
    }

    unsafe fn from_tbits(n: usize, dx: usize, x: *mut Self, mut ts: *const Self::Tbit) {
        Self::unfold_tbits(n, dx, x, |tx| {
            std::ptr::copy(ts, tx.as_mut_ptr(), tx.len());
            ts = ts.add(tx.len());
        });
    }

    /// Copy `n` tbits from `(dx,x)` slice into `(dy,y)`.
    unsafe fn copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        if n == 0 {
            return;
        }

        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let ry = dy % Self::SIZE;
        let mut yy = y.add(dy / Self::SIZE);
        let mut nn = n;

        if rx == ry {
            let mut xs = vec![Self::ZERO_TBIT; Self::SIZE];
            let mut ys = vec![Self::ZERO_TBIT; Self::SIZE];

            if rx != 0 {
                Self::word_to_tbits(*xx, xs.as_mut_ptr());
                Self::word_to_tbits(*yy, ys.as_mut_ptr());
                let d = std::cmp::min(n, Self::SIZE - rx);
                ys[ry..ry + d].copy_from_slice(&xs[rx..rx + d]);
                *yy = Self::word_from_tbits(ys.as_ptr());

                nn -= d;
                xx = xx.add(1);
                yy = yy.add(1);
            }

            std::ptr::copy(xx, yy, nn / Self::SIZE);

            xx = xx.add(nn / Self::SIZE);
            yy = yy.add(nn / Self::SIZE);
            nn = nn % Self::SIZE;

            if nn != 0 {
                Self::word_to_tbits(*xx, xs.as_mut_ptr());
                Self::word_to_tbits(*yy, ys.as_mut_ptr());
                ys[0..nn].copy_from_slice(&xs[0..nn]);
                *yy = Self::word_from_tbits(ys.as_ptr());
            }
        } else {
            // Rare case, just convert via tbits.
            let mut ts = vec![Self::ZERO_TBIT; n];
            Self::to_tbits(n, dx, x, ts.as_mut_ptr());
            Self::from_tbits(n, dy, y, ts.as_ptr());
        }
    }

    /// Set `n` tbits in `(dx,x)` slice to zero.
    unsafe fn set_zero(n: usize, dx: usize, x: *mut Self) {
        if n == 0 {
            return;
        }

        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let mut nn = n;
        let mut d;

        if rx != 0 {
            d = std::cmp::min(n, Self::SIZE - rx);
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            for i in rx..rx + d {
                *v.as_mut_ptr().add(i) = Self::ZERO_TBIT;
            }
            *xx = Self::word_from_tbits(v.as_ptr());
            nn -= d;
            xx = xx.add(1);
        }

        d = Self::SIZE;
        while nn >= d {
            *xx = Self::ZERO_WORD;
            nn -= d;
            xx = xx.add(1);
        }

        if nn > 0 {
            Self::word_to_tbits(*xx, v.as_mut_ptr());
            for i in 0..nn {
                *v.as_mut_ptr().add(i) = Self::ZERO_TBIT;
            }
            *xx = Self::word_from_tbits(v.as_ptr());
        }
    }

    /// Compare `n` tbits from `(dx,x)` slice into `(dy,y)`.
    unsafe fn equals(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool {
        if n == 0 {
            return true;
        }

        let rx = dx % Self::SIZE;
        let mut xx = x.add(dx / Self::SIZE);
        let ry = dy % Self::SIZE;
        let mut yy = y.add(dy / Self::SIZE);
        let mut nn = n;

        if rx == ry {
            let mut xs = vec![Self::ZERO_TBIT; Self::SIZE];
            let mut ys = vec![Self::ZERO_TBIT; Self::SIZE];

            if rx != 0 {
                Self::word_to_tbits(*xx, xs.as_mut_ptr());
                Self::word_to_tbits(*yy, ys.as_mut_ptr());
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
                Self::word_to_tbits(*xx, xs.as_mut_ptr());
                Self::word_to_tbits(*yy, ys.as_mut_ptr());
                if ys[0..nn] != xs[0..nn] {
                    return false;
                }
            }

            true
        } else {
            // Rare case, just convert via tbits.
            let mut xs = vec![Self::ZERO_TBIT; n];
            let mut ys = vec![Self::ZERO_TBIT; n];
            Self::to_tbits(n, dx, x, xs.as_mut_ptr());
            Self::to_tbits(n, dy, y, ys.as_mut_ptr());
            xs == ys
        }
    }
}

pub trait SpongosTbitWord: BasicTbitWord {
    // Spongos-related utils

    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit;
    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit;

    /// y:=x+s, s:=x, x:=y
    unsafe fn swap_add(n: usize, mut dx: usize, x: *mut Self, mut ds: usize, s: *mut Self) {
        for _ in 0..n {
            let tx = Self::get_tbit(dx, x);
            let ts = Self::get_tbit(ds, s);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dx, x, ty);
            dx += 1;
            ds += 1;
        }
    }
    /// x:=y-s, s:=x, y:=x
    unsafe fn swap_sub(n: usize, mut dy: usize, y: *mut Self, mut ds: usize, s: *mut Self) {
        for _ in 0..n {
            let ty = Self::get_tbit(dy, y);
            let ts = Self::get_tbit(ds, s);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dy, y, tx);
            dy += 1;
            ds += 1;
        }
    }
    /// y:=x+s, s:=x
    unsafe fn copy_add(
        n: usize,
        mut dx: usize,
        x: *const Self,
        mut ds: usize,
        s: *mut Self,
        mut dy: usize,
        y: *mut Self,
    ) {
        for _ in 0..n {
            let tx = Self::get_tbit(dx, x);
            let ts = Self::get_tbit(ds, s);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dy, y, ty);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }
    /// t:=y-s, s:=t, x:=t
    unsafe fn copy_sub(
        n: usize,
        mut dy: usize,
        y: *const Self,
        mut ds: usize,
        s: *mut Self,
        mut dx: usize,
        x: *mut Self,
    ) {
        for _ in 0..n {
            let ty = Self::get_tbit(dy, y);
            let ts = Self::get_tbit(ds, s);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dx, x, tx);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }
}


#[cfg(test)]
pub mod tests {
    use std::fmt;
    use super::*;
    use crate::tbits::{TbitSliceT, TbitsT};

    fn copy_range_tbits<TW>(m: usize, n: usize, ts: &[TW::Tbit])
        where
        TW: BasicTbitWord,
        TW::Tbit: fmt::Display + fmt::Debug,
    {
        //println!("copy_range_tbits m={} n={} ts={:?}", m, n, ts);
        let t0 = TbitsT::<TW>::from_tbits(&ts[..m]);
        let t1 = TbitsT::<TW>::from_tbits(&ts[m..n]);
        let t2 = TbitsT::<TW>::from_tbits(&ts[n..]);
        let t012 = TbitsT::<TW>::from_tbits(&ts);

        let to_tbits = |t: TbitSliceT<TW>| {
            let mut v = vec![TW::ZERO_TBIT; t.size()];
            t.get_tbits(&mut v[..]);
            v
        };

        let mut x0 = TbitsT::<TW>::zero(ts.len());
        x0.slice_mut().put_tbits(ts);
        assert_eq!(t012, x0);
        assert_eq!(ts, &to_tbits(x0.slice())[..]);

        let mut x1 = TbitsT::<TW>::zero(ts.len());
        x1.slice_mut().take(m).put_tbits(&ts[..m]);
        x1.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
        x1.slice_mut().drop(n).put_tbits(&ts[n..]);
        assert_eq!(t012, x1);
        assert_eq!(ts, &to_tbits(x1.slice())[..]);

        let mut x2 = TbitsT::<TW>::zero(ts.len());
        x2.slice_mut().drop(n).put_tbits(&ts[n..]);
        x2.slice_mut().take(m).put_tbits(&ts[..m]);
        x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
        assert_eq!(t012, x2);
        assert_eq!(t0.slice(), x2.slice().take(m));
        assert_eq!(t1.slice(), x2.slice().drop(m).take(n - m));
        assert_eq!(t2.slice(), x2.slice().drop(n));
        assert_eq!(ts, &to_tbits(x2.slice())[..]);
        assert_eq!(ts[..m], to_tbits(x2.slice().take(m))[..]);
        assert_eq!(ts[m..n], to_tbits(x2.slice().drop(m).take(n - m))[..]);
        assert_eq!(ts[n..], to_tbits(x2.slice().drop(n))[..]);
        x2.slice_mut().set_zero();
        x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
        x2.slice_mut().drop(n).put_tbits(&ts[n..]);
        x2.slice_mut().take(m).put_tbits(&ts[..m]);
        assert_eq!(t012, x2);
        x2.slice_mut().take(m).set_zero();
        x2.slice_mut().take(m).put_tbits(&ts[..m]);
        x2.slice_mut().drop(m).take(n - m).set_zero();
        x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
        x2.slice_mut().drop(n).set_zero();
        x2.slice_mut().drop(n).put_tbits(&ts[n..]);
        assert_eq!(t012, x2);
        x2.slice_mut().drop(m).take(n - m).set_zero();
        x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
        x2.slice_mut().drop(n).set_zero();
        x2.slice_mut().drop(n).put_tbits(&ts[n..]);
        x2.slice_mut().take(m).set_zero();
        x2.slice_mut().take(m).put_tbits(&ts[..m]);
        assert_eq!(t012, x2);

        let mut x3 = TbitsT::<TW>::zero(ts.len());
        t0.slice().copy(&x3.slice_mut().take(m));
        t1.slice().copy(&x3.slice_mut().drop(m).take(n - m));
        t2.slice().copy(&x3.slice_mut().drop(n));
        assert_eq!(t012, x3);
        assert_eq!(ts, &to_tbits(x3.slice())[..]);

        let mut x4 = TbitsT::<TW>::zero(ts.len());
        t2.slice().copy(&x4.slice_mut().drop(n));
        t0.slice().copy(&x4.slice_mut().take(m));
        t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
        assert_eq!(t012, x4);
        assert_eq!(ts, &to_tbits(x4.slice())[..]);

        x4.slice_mut().set_zero();
        t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
        t2.slice().copy(&x4.slice_mut().drop(n));
        t0.slice().copy(&x4.slice_mut().take(m));
        assert_eq!(t012, x4);
        x4.slice_mut().take(m).set_zero();
        t0.slice().copy(&x4.slice_mut().take(m));
        x4.slice_mut().drop(m).take(n - m).set_zero();
        t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
        x4.slice_mut().drop(n).set_zero();
        t2.slice().copy(&x4.slice_mut().drop(n));
        assert_eq!(t012, x4);
        x4.slice_mut().drop(m).take(n - m).set_zero();
        t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
        x4.slice_mut().drop(n).set_zero();
        t2.slice().copy(&x4.slice_mut().drop(n));
        x4.slice_mut().take(m).set_zero();
        t0.slice().copy(&x4.slice_mut().take(m));
        assert_eq!(t012, x4);
        assert_eq!(t0.slice(), x4.slice().take(m));
        assert_eq!(t1.slice(), x4.slice().drop(m).take(n - m));
        assert_eq!(t2.slice(), x4.slice().drop(n));
        assert_eq!(ts, &to_tbits(x4.slice())[..]);
        assert_eq!(ts[..m], to_tbits(x4.slice().take(m))[..]);
        assert_eq!(ts[m..n], to_tbits(x4.slice().drop(m).take(n - m))[..]);
        assert_eq!(ts[n..], to_tbits(x4.slice().drop(n))[..]);
    }

    pub fn copy_tbits<TW>(ts: &[TW::Tbit])
        where
        TW: BasicTbitWord,
        TW::Tbit: fmt::Display + fmt::Debug,
    {
        let s = ts.len();
        for m in 0..(s / 7 * 2 + 1) {
            for n in m..(s / 7 * 5 + 1) {
                for r in n..s {
                    copy_range_tbits::<TW>(m, n, &ts[..r]);
                }
            }
        }
    }
}
