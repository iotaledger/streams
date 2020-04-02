use super::*;
use crate::tbits::slice::*;

impl<'a, TW: 'a> TbitSlice<'a, TW>
where
    TW: TritWord,
{
    pub fn get_trit(&self) -> Trit {
        debug_assert!(!self.is_empty());
        unsafe { TW::get_tbit(self.r.d, self.p) }
    }
    pub fn get_tryte(&self) -> Tryte {
        debug_assert!(self.r.d + 3 <= self.r.n);
        unsafe { TW::get_tryte(self.r.d, self.p) }
    }
    pub fn get1s(&self, t1s: &mut [Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        unsafe {
            let mut d = self.r.d;
            for t in t1s {
                *t = TW::get1(d, self.p);
                d += 1;
            }
        }
    }
    pub fn get1(&self) -> Trint1 {
        debug_assert!(self.r.d < self.r.n);
        unsafe { TW::get1(self.r.d, self.p) }
    }
    pub fn get3(&self) -> Trint3 {
        debug_assert!(self.r.d + 3 <= self.r.n);
        unsafe { TW::get3(self.r.d, self.p) }
    }
    pub fn get6(&self) -> Trint6 {
        debug_assert!(self.r.d + 6 <= self.r.n);
        unsafe { TW::get6(self.r.d, self.p) }
    }
    pub fn get9(&self) -> Trint9 {
        debug_assert!(self.r.d + 9 <= self.r.n);
        unsafe { TW::get9(self.r.d, self.p) }
    }
    pub fn get18(&self) -> Trint18 {
        debug_assert!(self.r.d + 18 <= self.r.n);
        unsafe { TW::get18(self.r.d, self.p) }
    }
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW>
where
    TW: TritWord,
{
    pub fn put_trit(&mut self, t: Trit) {
        debug_assert!(!self.is_empty());
        unsafe { TW::put_tbit(self.r.d, self.p, t) }
    }
    pub fn put_tryte(&mut self, t: Tryte) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        unsafe { TW::put_tryte(self.r.d, self.p, t) }
    }
    pub fn put1s(&mut self, t1s: &[Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        unsafe {
            let mut d = self.r.d;
            for t in t1s {
                TW::put1(d, self.p, *t);
                d += 1;
            }
        }
    }
    pub fn put1(&mut self, t: Trint1) {
        debug_assert!(self.r.d < self.r.n);
        unsafe { TW::put1(self.r.d, self.p, t) }
    }
    pub fn put3(&mut self, t: Trint3) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        unsafe { TW::put3(self.r.d, self.p, t) }
    }
    pub fn put6(&mut self, t: Trint6) {
        debug_assert!(self.r.d + 6 <= self.r.n);
        unsafe { TW::put6(self.r.d, self.p, t) }
    }
    pub fn put9(&mut self, t: Trint9) {
        debug_assert!(self.r.d + 9 <= self.r.n);
        unsafe { TW::put9(self.r.d, self.p, t) }
    }
    pub fn put18(&mut self, t: Trint18) {
        debug_assert!(self.r.d + 18 <= self.r.n);
        unsafe { TW::put18(self.r.d, self.p, t) }
    }

    /// Increment trits in the range `[d..n)` as integer.
    pub fn inc(&mut self) -> bool {
        unsafe {
            let mut d = self.r.d;
            while d < self.r.n {
                let mut t = TW::get_tbit(d, self.p);
                t.0 = (t.0 + 1) % 3;
                TW::put_tbit(d, self.p, t);
                if 0 != t.0 {
                    return true;
                }
                d += 1;
            }
            false
        }
    }

    pub fn set_trit(&mut self, t: Trit) {
        debug_assert!(t.0 < 3);
        unsafe {
            let mut d = self.r.d;
            while d < self.r.n {
                TW::put_tbit(d, self.p, t);
                d += 1;
            }
        }
    }
}
