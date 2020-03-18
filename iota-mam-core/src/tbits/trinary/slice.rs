use crate::tbits::slice::*;
use super::*;

impl<'a, TW: 'a> TbitSliceT<'a, TW>
where
    TW: TritWord,
{
    pub fn get_trit(&self) -> Trit {
        unsafe {
            debug_assert!(!self.is_empty());
            TW::get_tbit(self.r.d, self.p)
        }
    }
    pub fn get_tryte(&self) -> Tryte {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::get_tryte(self.r.d, self.p)
    }
    pub fn get1s(&self, t1s: &mut [Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        let mut d = self.r.d;
        for t in t1s {
            *t = TW::get1(d, self.p);
            d += 1;
        }
    }
    pub fn get1(&self) -> Trint1 {
        debug_assert!(self.r.d < self.r.n);
        TW::get1(self.r.d, self.p)
    }
    pub fn get3(&self) -> Trint3 {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::get3(self.r.d, self.p)
    }
    pub fn get6(&self) -> Trint6 {
        debug_assert!(self.r.d + 6 <= self.r.n);
        TW::get6(self.r.d, self.p)
    }
    pub fn get9(&self) -> Trint9 {
        debug_assert!(self.r.d + 9 <= self.r.n);
        TW::get9(self.r.d, self.p)
    }
    pub fn get18(&self) -> Trint18 {
        debug_assert!(self.r.d + 18 <= self.r.n);
        TW::get18(self.r.d, self.p)
    }
    /// Get a tryte at the current offset and ASCII-convert it as char.
    pub fn get_char(&self) -> char {
        TW::get_char(self.size_min(3), self.r.d, self.p)
    }

    /// ASCII encode trytes at the current offset.
    /// The last incomplete tryte if any is padded with zero trits.
    pub fn to_str(&self) -> String {
        let mut s = String::with_capacity((self.size() + 2) / 3);
        let mut d = self.r.d;
        while d < self.r.n {
            s.push(TW::get_char(self.r.n - d, d, self.p));
            d += 3;
        }
        s
    }

    pub fn eq_str(&self, s: &str) -> bool {
        if (self.size() + 2) / 3 != s.len() {
            return false;
        }

        let mut d = self.r.d;
        for c in s.chars() {
            let c2 = TW::get_char(self.r.n - d, d, self.p);
            if c != c2 {
                return false;
            }
            d += 3;
        }
        true
    }

}

impl<'a, TW: 'a> TbitSliceMutT<'a, TW>
where
    TW: TritWord,
{
    pub fn put_trit(&mut self, t: Trit) {
        unsafe {
            debug_assert!(!self.is_empty());
            TW::put_tbit(self.r.d, self.p, t)
        }
    }
    pub fn put_tryte(&mut self, t: Tryte) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::put_tryte(self.r.d, self.p, t)
    }
    pub fn put1s(&mut self, t1s: &[Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        let mut d = self.r.d;
        for t in t1s {
            TW::put1(d, self.p, *t);
            d += 1;
        }
    }
    pub fn put1(&mut self, t: Trint1) {
        debug_assert!(self.r.d < self.r.n);
        TW::put1(self.r.d, self.p, t)
    }
    pub fn put3(&mut self, t: Trint3) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::put3(self.r.d, self.p, t)
    }
    pub fn put6(&mut self, t: Trint6) {
        debug_assert!(self.r.d + 6 <= self.r.n);
        TW::put6(self.r.d, self.p, t)
    }
    pub fn put9(&mut self, t: Trint9) {
        debug_assert!(self.r.d + 9 <= self.r.n);
        TW::put9(self.r.d, self.p, t)
    }
    pub fn put18(&mut self, t: Trint18) {
        debug_assert!(self.r.d + 18 <= self.r.n);
        TW::put18(self.r.d, self.p, t)
    }
    /// Try to ASCII-convert a char `c` to a tryte and put it at the current offset.
    pub fn put_char(&mut self, c: char) -> bool {
        TW::put_char(self.size_min(3), self.r.d, self.p, c)
    }
    /// Try to ASCII-convert string `s` to trytes and put them at the current offset.
    /// If the length of `s` exceeds the size of the slice the remaining trits of `s` must be zero.
    pub fn from_str(&mut self, s: &str) -> bool {
        let mut d = self.r.d;
        for c in s.chars() {
            if d >= self.r.n {
                break;
            }
            if !TW::put_char(self.r.n - d, d, self.p, c) {
                return false;
            }
            d += 3;
        }
        true
    }

    /// Increment trits in the range `[d..n)` as integer.
    pub fn inc(&mut self) -> bool {
        let mut d = self.r.d;
        while d < self.r.n {
            unsafe {
                let mut t = TW::get_tbit(d, self.p);
                t.0 = (t.0 + 1) % 3;
                TW::put_tbit(d, self.p, t);
                if 0 != t.0 {
                    return true;
                }
            }
            d += 1;
        }
        false
    }

    pub fn set_trit(&mut self, t: Trit) {
        debug_assert!(t.0 < 3);
        let mut d = self.r.d;
        while d < self.r.n {
            unsafe { TW::put_tbit(d, self.p, t); }
            d += 1;
        }
    }
}
