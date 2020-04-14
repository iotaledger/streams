use std::fmt;

/// Abstraction for a binary/trinary word containing one or several tbits (bits/trits).
/// The size and encoding of the word is defined by the implementation.
/// Many functions take a pair `(d,p)` encoding a slice of tbits as input where
/// `d` is the current tbit offset, `p` is the raw pointer to the first word in a slice.
pub trait BasicTbitWord: Sized + Copy + PartialEq {
    /// The number of tbits per word.
    const SIZE: usize;
    /// Trit or bit.
    type Tbit: Sized + Copy + PartialEq + fmt::Display;

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

    unsafe fn fold_tbits<F>(mut s: usize, mut dx: usize, mut x: *const Self, mut f: F)
    where
        F: FnMut(&[Self::Tbit]),
    {
        if s == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        x = x.add(dx / Self::SIZE);
        dx = dx % Self::SIZE;

        if dx != 0 {
            let d = std::cmp::min(s, Self::SIZE - dx);
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&v[dx..dx + d]);
            s -= d;
            x = x.add(1);
        }

        while s >= Self::SIZE {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&v[..]);
            s -= Self::SIZE;
            x = x.add(1);
        }

        if s > 0 {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&v[..s]);
        }
    }

    unsafe fn refold_tbits<F>(mut s: usize, mut dx: usize, mut x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Self::Tbit]),
    {
        if s == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        x = x.add(dx / Self::SIZE);
        dx = dx % Self::SIZE;

        if dx != 0 {
            let d = std::cmp::min(s, Self::SIZE - dx);
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&mut v[dx..dx + d]);
            *x = Self::word_from_tbits(v.as_ptr());
            s -= d;
            x = x.add(1);
        }

        while s >= Self::SIZE {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&mut v[..]);
            *x = Self::word_from_tbits(v.as_ptr());
            s -= Self::SIZE;
            x = x.add(1);
        }

        if s > 0 {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&mut v[..s]);
            *x = Self::word_from_tbits(v.as_ptr());
        }
    }

    unsafe fn unfold_tbits<F>(mut s: usize, mut dx: usize, mut x: *mut Self, mut f: F)
    where
        F: FnMut(&mut [Self::Tbit]),
    {
        if s == 0 {
            return;
        }

        // Primitive array `[Self::Tbit; Self::SIZE]` is not supported yet.
        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        x = x.add(dx / Self::SIZE);
        dx = dx % Self::SIZE;

        if dx != 0 {
            let d = std::cmp::min(s, Self::SIZE - dx);
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&mut v[dx..dx + d]);
            *x = Self::word_from_tbits(v.as_ptr());
            s -= d;
            x = x.add(1);
        }

        while s >= Self::SIZE {
            f(&mut v[..]);
            *x = Self::word_from_tbits(v.as_ptr());
            s -= Self::SIZE;
            x = x.add(1);
        }

        if s > 0 {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            f(&mut v[..s]);
            *x = Self::word_from_tbits(v.as_ptr());
        }
    }

    unsafe fn to_tbits(s: usize, dx: usize, x: *const Self, mut ts: *mut Self::Tbit) {
        Self::fold_tbits(s, dx, x, |tx| {
            std::ptr::copy(tx.as_ptr(), ts, tx.len());
            ts = ts.add(tx.len());
        });
    }

    unsafe fn from_tbits(s: usize, dx: usize, x: *mut Self, mut ts: *const Self::Tbit) {
        Self::unfold_tbits(s, dx, x, |tx| {
            std::ptr::copy(ts, tx.as_mut_ptr(), tx.len());
            ts = ts.add(tx.len());
        });
    }

    /// Copy `s` tbits from `(dx,x)` slice into `(dy,y)`.
    unsafe fn copy(mut s: usize, mut dx: usize, mut x: *const Self, mut dy: usize, mut y: *mut Self) {
        if s == 0 {
            return;
        }

        if dx % Self::SIZE == dy % Self::SIZE {
            x = x.add(dx / Self::SIZE);
            dx = dx % Self::SIZE;
            y = y.add(dy / Self::SIZE);
            dy = dy % Self::SIZE;

            let mut xs = vec![Self::ZERO_TBIT; Self::SIZE];
            let mut ys = vec![Self::ZERO_TBIT; Self::SIZE];

            if dx != 0 {
                Self::word_to_tbits(*x, xs.as_mut_ptr());
                Self::word_to_tbits(*y, ys.as_mut_ptr());
                let d = std::cmp::min(s, Self::SIZE - dx);
                ys[dy..dy + d].copy_from_slice(&xs[dx..dx + d]);
                *y = Self::word_from_tbits(ys.as_ptr());

                s -= d;
                x = x.add(1);
                y = y.add(1);
            }

            std::ptr::copy(x, y, s / Self::SIZE);

            x = x.add(s / Self::SIZE);
            y = y.add(s / Self::SIZE);
            s = s % Self::SIZE;

            if s != 0 {
                Self::word_to_tbits(*x, xs.as_mut_ptr());
                Self::word_to_tbits(*y, ys.as_mut_ptr());
                ys[0..s].copy_from_slice(&xs[0..s]);
                *y = Self::word_from_tbits(ys.as_ptr());
            }
        } else {
            // Rare case, just convert via tbits.
            let mut ts = vec![Self::ZERO_TBIT; s];
            Self::to_tbits(s, dx, x, ts.as_mut_ptr());
            Self::from_tbits(s, dy, y, ts.as_ptr());
        }
    }

    /// Set `n` tbits in `(dx,x)` slice to zero.
    unsafe fn set_zero(mut s: usize, mut dx: usize, mut x: *mut Self) {
        if s == 0 {
            return;
        }

        let mut v = vec![Self::ZERO_TBIT; Self::SIZE];
        x = x.add(dx / Self::SIZE);
        dx = dx % Self::SIZE;

        if dx != 0 {
            let d = std::cmp::min(s, Self::SIZE - dx);
            Self::word_to_tbits(*x, v.as_mut_ptr());
            for i in dx..dx + d {
                // This should disable run-time bounds check.
                *v.as_mut_ptr().add(i) = Self::ZERO_TBIT;
            }
            *x = Self::word_from_tbits(v.as_ptr());
            s -= d;
            x = x.add(1);
        }

        while s >= Self::SIZE {
            *x = Self::ZERO_WORD;
            s -= Self::SIZE;
            x = x.add(1);
        }

        if s > 0 {
            Self::word_to_tbits(*x, v.as_mut_ptr());
            for i in 0..s {
                *v.as_mut_ptr().add(i) = Self::ZERO_TBIT;
            }
            *x = Self::word_from_tbits(v.as_ptr());
        }
    }

    /// Compare `n` tbits from `(dx,x)` slice into `(dy,y)`.
    unsafe fn equals(mut s: usize, mut dx: usize, mut x: *const Self, mut dy: usize, mut y: *const Self) -> bool {
        if s == 0 {
            return true;
        }

        if dx % Self::SIZE == dy % Self::SIZE {
            x = x.add(dx / Self::SIZE);
            dx = dx % Self::SIZE;
            y = y.add(dy / Self::SIZE);
            dy = dy % Self::SIZE;

            let mut xs = vec![Self::ZERO_TBIT; Self::SIZE];
            let mut ys = vec![Self::ZERO_TBIT; Self::SIZE];

            if dx != 0 {
                Self::word_to_tbits(*x, xs.as_mut_ptr());
                Self::word_to_tbits(*y, ys.as_mut_ptr());
                let d = std::cmp::min(s, Self::SIZE - dx);
                if ys[dy..dy + d] != xs[dx..dx + d] {
                    return false;
                }

                s -= d;
                x = x.add(1);
                y = y.add(1);
            }

            while s >= Self::SIZE {
                if *x != *y {
                    return false;
                }
                s -= Self::SIZE;
                x = x.add(1);
                y = y.add(1);
            }

            x = x.add(s / Self::SIZE);
            y = y.add(s / Self::SIZE);
            s = s % Self::SIZE;

            if s != 0 {
                Self::word_to_tbits(*x, xs.as_mut_ptr());
                Self::word_to_tbits(*y, ys.as_mut_ptr());
                if ys[0..s] != xs[0..s] {
                    return false;
                }
            }

            true
        } else {
            // Rare case, just convert via tbits.
            let mut xs = vec![Self::ZERO_TBIT; s];
            let mut ys = vec![Self::ZERO_TBIT; s];
            Self::to_tbits(s, dx, x, xs.as_mut_ptr());
            Self::to_tbits(s, dy, y, ys.as_mut_ptr());
            xs == ys
        }
    }
}

pub trait StringTbitWord: BasicTbitWord {
    const TBITS_PER_CHAR: usize;
    unsafe fn put_char(s: usize, d: usize, p: *mut Self, c: char) -> bool;
    unsafe fn get_char(s: usize, d: usize, p: *const Self) -> char;
}

pub trait IntTbitWord: BasicTbitWord {
    unsafe fn put_isize(n: usize, d: usize, p: *mut Self, i: isize);
    unsafe fn get_isize(n: usize, d: usize, p: *const Self) -> isize;
    unsafe fn put_usize(n: usize, d: usize, p: *mut Self, u: usize);
    unsafe fn get_usize(n: usize, d: usize, p: *const Self) -> usize;
}

pub trait SpongosTbitWord: BasicTbitWord {
    // Spongos-related utils

    /// x+y
    fn tbit_add(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit;
    /// x-y
    fn tbit_sub(x: Self::Tbit, y: Self::Tbit) -> Self::Tbit;

    /// s:=s+x
    unsafe fn add(mut ds: usize, s: *mut Self, n: usize, mut dx: usize, x: *const Self) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let tx = Self::get_tbit(dx, x);
            let ty = Self::tbit_add(ts, tx);
            Self::put_tbit(ds, s, ty);
            dx += 1;
            ds += 1;
        }
    }

    /// y:=x+s, s:=x, x:=y
    unsafe fn setx_add_mut(mut ds: usize, s: *mut Self, n: usize, mut dx: usize, x: *mut Self) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let tx = Self::get_tbit(dx, x);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dx, x, ty);
            dx += 1;
            ds += 1;
        }
    }
    /// x:=y-s, s:=x, y:=x
    unsafe fn setx_sub_mut(mut ds: usize, s: *mut Self, n: usize, mut dy: usize, y: *mut Self) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let ty = Self::get_tbit(dy, y);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dy, y, tx);
            dy += 1;
            ds += 1;
        }
    }
    /// y:=x+s, s:=x
    unsafe fn setx_add(
        mut ds: usize,
        s: *mut Self,
        n: usize,
        mut dx: usize,
        x: *const Self,
        mut dy: usize,
        y: *mut Self,
    ) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let tx = Self::get_tbit(dx, x);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dy, y, ty);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }
    /// x:=y-s, s:=x
    unsafe fn setx_sub(
        mut ds: usize,
        s: *mut Self,
        n: usize,
        mut dy: usize,
        y: *const Self,
        mut dx: usize,
        x: *mut Self,
    ) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let ty = Self::get_tbit(dy, y);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, tx);
            Self::put_tbit(dx, x, tx);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }

    /// y:=x+s, s:=y, x:=y
    unsafe fn sety_add_mut(mut ds: usize, s: *mut Self, n: usize, mut dx: usize, x: *mut Self) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let tx = Self::get_tbit(dx, x);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, ty);
            Self::put_tbit(dx, x, ty);
            dx += 1;
            ds += 1;
        }
    }
    /// x:=y-s, s:=y, y:=x
    unsafe fn sety_sub_mut(mut ds: usize, s: *mut Self, n: usize, mut dy: usize, y: *mut Self) {
        for _ in 0..n {
            let ts = Self::get_tbit(ds, s);
            let ty = Self::get_tbit(dy, y);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, ty);
            Self::put_tbit(dy, y, tx);
            dy += 1;
            ds += 1;
        }
    }
    /// y:=x+s, s:=y
    unsafe fn sety_add(
        mut ds: usize,
        s: *mut Self,
        n: usize,
        mut dx: usize,
        x: *const Self,
        mut dy: usize,
        y: *mut Self,
    ) {
        for _ in 0..n {
            let tx = Self::get_tbit(dx, x);
            let ts = Self::get_tbit(ds, s);
            let ty = Self::tbit_add(tx, ts);
            Self::put_tbit(ds, s, ty);
            Self::put_tbit(dy, y, ty);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }
    /// x:=y-s, s:=y
    unsafe fn sety_sub(
        mut ds: usize,
        s: *mut Self,
        n: usize,
        mut dy: usize,
        y: *const Self,
        mut dx: usize,
        x: *mut Self,
    ) {
        for _ in 0..n {
            let ty = Self::get_tbit(dy, y);
            let ts = Self::get_tbit(ds, s);
            let tx = Self::tbit_sub(ty, ts);
            Self::put_tbit(ds, s, ty);
            Self::put_tbit(dx, x, tx);
            dx += 1;
            ds += 1;
            dy += 1;
        }
    }

    /// Absorb plain tbits `x` into state `s`, OVERWRITE mode.
    unsafe fn absorb_overwrite(ds: usize, s: *mut Self, n: usize, dx: usize, x: *const Self) {
        Self::copy(n, dx, x, ds, s);
    }
    /// Absorb plain tbits `x` into state `s`, ADD/XOR mode.
    unsafe fn absorb_xor(ds: usize, s: *mut Self, n: usize, dx: usize, x: *const Self) {
        Self::add(ds, s, n, dx, x);
    }

    /// Squeeze tbits `y` from state `s`, OVERWRITE mode.
    unsafe fn squeeze_overwrite(ds: usize, s: *mut Self, n: usize, dy: usize, y: *mut Self) {
        Self::copy(n, ds, s, dy, y);
        Self::set_zero(n, ds, s);
    }
    /// Squeeze tbits `y` from state `s`, ADD/XOR mode.
    unsafe fn squeeze_xor(ds: usize, s: *mut Self, n: usize, dy: usize, y: *mut Self) {
        Self::copy(n, ds, s, dy, y);
    }

    /// Squeeze tbits `y` from state `s`, OVERWRITE mode.
    unsafe fn squeeze_eq_overwrite(ds: usize, s: *mut Self, n: usize, dy: usize, y: *const Self) -> bool {
        let r = Self::equals(n, ds, s as *const Self, dy, y);
        Self::set_zero(n, ds, s);
        r
    }
    /// Squeeze tbits `y` from state `s`, ADD/XOR mode.
    unsafe fn squeeze_eq_xor(ds: usize, s: *mut Self, n: usize, dy: usize, y: *const Self) -> bool {
        Self::equals(n, ds, s as *const Self, dy, y)
    }

    /// Encrypt tbits `x` into `y` with state `s`, OVERWRITE mode.
    unsafe fn encrypt_overwrite(ds: usize, s: *mut Self, n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        Self::setx_add(ds, s, n, dx, x, dy, y);
    }
    /// Encrypt tbits `x` with state `s`, OVERWRITE mode.
    unsafe fn encrypt_overwrite_mut(ds: usize, s: *mut Self, n: usize, dx: usize, x: *mut Self) {
        Self::setx_add_mut(ds, s, n, dx, x);
    }
    /// Encrypt tbits `y` with state `s`, ADD/XOR mode.
    unsafe fn encrypt_xor(ds: usize, s: *mut Self, n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        Self::sety_add(ds, s, n, dx, x, dy, y);
    }
    /// Encrypt tbits `x` with state `s`, ADD/XOR mode.
    unsafe fn encrypt_xor_mut(ds: usize, s: *mut Self, n: usize, dx: usize, x: *mut Self) {
        Self::sety_add_mut(ds, s, n, dx, x);
    }

    /// Decrypt tbits `y` into `x` with state `s`, OVERWRITE mode.
    unsafe fn decrypt_overwrite(ds: usize, s: *mut Self, n: usize, dy: usize, y: *const Self, dx: usize, x: *mut Self) {
        Self::setx_sub(ds, s, n, dy, y, dx, x);
    }
    /// Decrypt tbits `y` with state `s`, OVERWRITE mode.
    unsafe fn decrypt_overwrite_mut(ds: usize, s: *mut Self, n: usize, dy: usize, y: *mut Self) {
        Self::setx_sub_mut(ds, s, n, dy, y);
    }
    /// Decrypt tbits `y` into `x` with state `s`, ADD/XOR mode.
    unsafe fn decrypt_xor(ds: usize, s: *mut Self, n: usize, dy: usize, y: *const Self, dx: usize, x: *mut Self) {
        Self::sety_sub(ds, s, n, dy, y, dx, x);
    }
    /// Decrypt tbits `y` with state `s`, ADD/XOR mode.
    unsafe fn decrypt_xor_mut(ds: usize, s: *mut Self, n: usize, dy: usize, y: *mut Self) {
        Self::sety_sub_mut(ds, s, n, dy, y);
    }
}

pub trait RngTbitWord: BasicTbitWord + super::convert::IConvertOnto<super::binary::Byte> {}
