use std::fmt::{Display, Formatter, Write, Error};

/// Unsigned trit type with values in range 0..2. Used by Troika implementation.
pub type Trit = u8; //0..2
/// Unsigned tryte type.
pub type Tryte = u8; //0..26

/// Signed trit type: -1..1.
pub type Trint1 = i8;
/// Signed tryte type: -13..13.
pub type Trint3 = i8;
/// Signed 6-trit integer type.
pub type Trint6 = i16;
/// Signed 9-trit integer type.
pub type Trint9 = i16;
/// Signed 18-trit integer type.
pub type Trint18 = i32;

fn mods_m32(t: i32, m: i32) -> (i32, i32) {
    let r: i32 = (((t % m) + m + (m-1)/2) % m) - (m-1)/2;
    let q: i32 = (t - r) / m;
    (r, q)
}
/// Remainder r and quotient q of t mods 3^1: t == r * 3^1 + q.
pub fn mods1(t: i32) -> (Trint1, i32) {
    let (r, q) = mods_m32(t, 3);
    (r as Trint1, q)
}
/// Remainder r and quotient q of t mods 3^3: t == r * 3^3 + q.
pub fn mods3(t: i32) -> (Trint3, i32) {
    let (r, q) = mods_m32(t, 27);
    (r as Trint3, q)
}
/// Remainder r and quotient q of t mods 3^9: t == r * 3^9 + q.
pub fn mods9(t: i32) -> (Trint9, i32) {
    let (r, q) = mods_m32(t, 19683);
    (r as Trint9, q)
}

fn tryte_from_char(c: char) -> Option<Tryte> {
    if 'A' <= c && c <= 'Z' {
        Some(c as Tryte - 'A' as Tryte + 1)
    } else if '9' == c {
        Some(0)
    } else {
        None
    }
}
fn tryte_to_char(t: Tryte) -> char {
    assert!(t < 27);
    if t == 0 {
        '9'
    } else {
        (t - 1 + 'A' as Tryte) as char
    }
}

/// Abstraction for a trinary word containing one or several trits.
/// The size and encoding of trinary word is defined by the implementation.
/// Many functions take a pair `(d,p)` encoding a slice of trits as input where
/// `d` is the current trit offset, `p` is the raw pointer to the first word in a slice. 
pub trait TritWord {
    /// The number of trits per word.
    const SIZE: usize;

    /// All-zero trits word.
    fn zero() -> Self;
    /// Copy `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self);
    /// Set `n` trits in `(d,p)` slice to zero.
    fn unsafe_set_zero(n: usize, d: usize, p: *mut Self);
    /// Compare `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_eq(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool;

    // Integer conversion utils

    fn put_trit(d: usize, p: *mut Self, t: Trit);
    fn get_trit(d: usize, p: *const Self) -> Trit;
    fn put_tryte(d: usize, p: *mut Self, t: Tryte);
    fn get_tryte(d: usize, p: *const Self) -> Tryte;
    fn put1(d: usize, p: *mut Self, t: Trint1);
    fn get1(d: usize, p: *const Self) -> Trint1;
    fn put3(d: usize, p: *mut Self, t: Trint3);
    fn get3(d: usize, p: *const Self) -> Trint3;
    fn put6(d: usize, p: *mut Self, t: Trint6);
    fn get6(d: usize, p: *const Self) -> Trint6;
    fn put9(d: usize, p: *mut Self, t: Trint9);
    fn get9(d: usize, p: *const Self) -> Trint9;
    fn put18(d: usize, p: *mut Self, t: Trint18);
    fn get18(d: usize, p: *const Self) -> Trint18;

    // Spongos-related utils

    /// y:=x+s, s:=x, x:=y
    fn unsafe_swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self);
    /// x:=y-s, s:=x, y:=x
    fn unsafe_swap_sub(n: usize, dy: usize, y: *mut Self, ds: usize, s: *mut Self);
    /// y:=x+s, s:=x
    fn unsafe_copy_add(n: usize, dx: usize, x: *const Self, ds: usize, s: *mut Self, dy: usize, y: *mut Self);
    /// t:=y-s, s:=t, x:=t
    fn unsafe_copy_sub(n: usize, dy: usize, y: *const Self, ds: usize, s: *mut Self, dx: usize, x: *mut Self);
}

impl TritWord for Trit {
    const SIZE: usize = 1;

    fn zero() -> Self {
        0
    }
    fn unsafe_copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self) {
        unsafe { std::ptr::copy(x.add(dx), y.add(dy), n); }
    }
    fn unsafe_set_zero(n: usize, d: usize, p: *mut Self) {
        unsafe { std::ptr::write_bytes(p.add(d), 0, n); }
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
        unsafe{ *(p.add(d)) = t; }
    }
    fn get_trit(d: usize, p: *const Self) -> Trit {
        unsafe { *(p.add(d)) }
    }
    fn put_tryte(d: usize, p: *mut Self, t: Tryte) {
        assert!(t < 27);
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
    fn unsafe_copy_add(n: usize, dx: usize, x: *const Self, ds: usize, s: *mut Self, dy: usize, y: *mut Self) {
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
    fn unsafe_copy_sub(n: usize, dy: usize, y: *const Self, ds: usize, s: *mut Self, dx: usize, x: *mut Self) {
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

//TODO: fix TW and use static arrays in spongos, wots, mss, ... instead of Trits<TW>

#[derive(Clone)]
pub struct Trits<TW> {
    n: usize,
    buf: std::vec::Vec<TW>,
}

impl<TW> Trits<TW> where TW: TritWord + Copy {
    pub fn zero(n: usize) -> Self {
        Self {
            n: n,
            buf: vec![TW::zero(); (n + TW::SIZE - 1) / TW::SIZE]
        }
    }
    pub fn slice(&self) -> TritConstSlice<TW> {
        TritConstSlice::<TW>::from_trits(self)
    }
    pub fn mut_slice(&mut self) -> TritMutSlice<TW> {
        TritMutSlice::<TW>::from_mut_trits(self)
    }
    pub fn buf_len(&self) -> usize {
        self.buf.len()
    }
    pub fn size(&self) -> usize {
        self.n
    }
}

#[derive(Copy, Clone)]
pub struct TritConstSlice<TW> {
    n: usize, // size in trits
    d: usize, // offset in trits; d < n
    p: *const TW, // slice
}
#[derive(Copy, Clone)]
pub struct TritMutSlice<TW> {
    n: usize, // size in trits
    d: usize, // offset in trits; d < n
    p: *mut TW, // slice
}

impl<TW> TritConstSlice<TW> where TW: TritWord + Copy {
    pub fn clone_trits(self) -> Trits<TW>
    {
        let mut t = Trits::<TW>::zero(self.size());
        self.copy(t.mut_slice());
        t
    }
    pub fn from_trits(t: &Trits<TW>) -> Self {
        Self {
            n: t.size(),
            d: 0,
            p: t.buf.as_ptr(),
        }
    }
    pub fn from_slice(n: usize, t: &[TW]) -> Self {
        assert!(n <= t.len() * TW::SIZE);
        Self {
            n: n,
            d: 0,
            p: t.as_ptr(),
        }
    }

    pub fn get_trit(self) -> Trit {
        TW::get_trit(self.d, self.p)
    }
    pub fn get_trits(mut self, trits: &mut [Trit]) {
        assert!(self.size() >= trits.len());
        for t in trits {
            *t = self.get_trit();
            self = self.drop(1);
        }
    }
    pub fn get_tryte(self) -> Tryte {
        assert!(self.d + 3 <= self.n);
        TW::get_tryte(self.d, self.p)
    }
    pub fn get1(self) -> Trint1 {
        assert!(self.d + 1 <= self.n);
        TW::get1(self.d, self.p)
    }
    pub fn get3(self) -> Trint3 {
        assert!(self.d + 3 <= self.n);
        TW::get3(self.d, self.p)
    }
    pub fn get6(self) -> Trint6 {
        assert!(self.d + 6 <= self.n);
        TW::get6(self.d, self.p)
    }
    pub fn get9(self) -> Trint9 {
        assert!(self.d + 9 <= self.n);
        TW::get9(self.d, self.p)
    }
    pub fn get18(self) -> Trint18 {
        assert!(self.d + 18 <= self.n);
        TW::get18(self.d, self.p)
    }
    pub fn get_char(self) -> char {
        let mut ts: [Trit; 3] = [0; 3];
        self.get_trits(&mut ts[0..self.size_min(3)]);
        let t = 0 + 1 * (ts[0] as Tryte) + 3 * (ts[1] as Tryte) + 9 * (ts[2] as Tryte);
        tryte_to_char(t)
    }
    pub fn to_str(mut self) -> String {
        let mut s = String::with_capacity((self.size() + 2) / 3);
        while !self.is_empty() {
            s.push(self.get_char());
            self = self.drop_min(3);
        }
        s
    }

    pub fn is_same(self, x: Self) -> bool {
        unsafe {
            true
                && self.p.add(self.d / TW::SIZE) == x.p.add(self.d / TW::SIZE)
                && (self.d % TW::SIZE) == (x.d % TW::SIZE)
        }
        //self.p == x.p && self.d == x.d //&& self.n == x.n
    }
    pub fn is_overlapped(self, x: Self) -> bool {
        unsafe {
            let begin = self.p.add(self.d / TW::SIZE);
            let end = self.p.add((self.n + TW::SIZE - 1) / TW::SIZE);
            let x_begin = x.p.add(x.d / TW::SIZE);
            let x_end = x.p.add((x.n + TW::SIZE - 1) / TW::SIZE);
            !(x_end <= begin || end <= x_begin)
        }
    }
    #[inline]
    pub fn is_empty(self) -> bool {
        self.n == self.d
    }
    #[inline]
    pub fn total_size(self) -> usize {
        self.n
    }
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        std::cmp::min(self.size(), s)
    }
    #[inline]
    pub fn take(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.d + n,
            d: self.d,
            p: self.p,
        }
    }
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        Self {
            n: std::cmp::min(self.n, self.d + n),
            d: self.d,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.n,
            d: self.d + n,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        Self {
            n: self.n,
            d: std::cmp::min(self.n, self.d + n),
            p: self.p,
        }
    }
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        assert!(self.d >= n);
        Self {
            n: self.n,
            d: self.d - n,
            p: self.p,
        }
    }
    #[inline]
    pub fn pickup_all(self) -> Self {
        Self {
            n: self.n,
            d: 0,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop_all(self) -> Self {
        Self {
            n: self.n,
            d: self.n,
            p: self.p,
        }
    }
    #[inline]
    pub fn dropped(self) -> Self {
        Self {
            n: self.d,
            d: 0,
            p: self.p,
        }
    }
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let t = self.take(n);
        *self = self.drop(n);
        t
    }

    pub fn copy(self, to: TritMutSlice<TW>) {
        debug_assert!(self.size() == to.size());
        //TODO: is_same(to) || !is_overlapped(to)
        TW::unsafe_copy(self.size(), self.d, self.p, to.d, to.p);
    }
    pub fn copy_min(self, to: TritMutSlice<TW>) -> usize {
        let n = std::cmp::min(self.size(), to.size());
        self.take(n).copy(to.take(n));
        n
    }

    pub fn copy_add(self, s: TritMutSlice<TW>, y: TritMutSlice<TW>) {
        assert!(self.size() == y.size());
        assert!(self.size() == s.size());
        TW::unsafe_copy_add(self.size(), self.d, self.p, s.d, s.p, y.d, y.p);
    }
    pub fn copy_add_min(self, s: TritMutSlice<TW>, y: TritMutSlice<TW>) -> usize {
        assert!(self.size() == y.size());
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).copy_add(s.take(n), y.take(n));
        n
    }
    pub fn copy_sub(self, s: TritMutSlice<TW>, y: TritMutSlice<TW>) {
        assert!(self.size() == y.size());
        assert!(self.size() == s.size());
        TW::unsafe_copy_sub(self.size(), self.d, self.p, s.d, s.p, y.d, y.p);
    }
    pub fn copy_sub_min(self, s: TritMutSlice<TW>, y: TritMutSlice<TW>) -> usize {
        assert!(self.size() == y.size());
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).copy_sub(s.take(n), y.take(n));
        n
    }
}

impl<TW> TritMutSlice<TW> where TW: TritWord + Copy {
    pub fn as_const(self) -> TritConstSlice<TW> {
        TritConstSlice::<TW> {
            n: self.n,
            d: self.d,
            p: self.p,
        }
    }
    pub fn from_mut_trits(t: &mut Trits<TW>) -> Self {
        Self {
            n: t.size(),
            d: 0,
            p: t.buf.as_mut_ptr(),
        }
    }
    pub fn from_mut_slice(n: usize, t: &mut [TW]) -> Self {
        assert!(n <= t.len() * TW::SIZE);
        Self {
            n: n,
            d: 0,
            p: t.as_mut_ptr(),
        }
    }

    pub fn put_trit(self, t: Trit) {
        TW::put_trit(self.d, self.p, t)
    }
    pub fn put_trits(mut self, trits: &[Trit]) {
        assert!(self.size() >= trits.len());
        for t in trits {
            self.put_trit(*t);
            self = self.drop(1);
        }
    }
    pub fn put_tryte(self, t: Tryte) {
        assert!(self.d + 3 <= self.n);
        TW::put_tryte(self.d, self.p, t)
    }
    pub fn put1(self, t: Trint1) {
        assert!(self.d + 1 <= self.n);
        TW::put1(self.d, self.p, t)
    }
    pub fn put3(self, t: Trint3) {
        assert!(self.d + 3 <= self.n);
        TW::put3(self.d, self.p, t)
    }
    pub fn put6(self, t: Trint6) {
        assert!(self.d + 6 <= self.n);
        TW::put6(self.d, self.p, t)
    }
    pub fn put9(self, t: Trint9) {
        assert!(self.d + 9 <= self.n);
        TW::put9(self.d, self.p, t)
    }
    pub fn put18(self, t: Trint18) {
        assert!(self.d + 18 <= self.n);
        TW::put18(self.d, self.p, t)
    }
    pub fn put_char(self, c: char) -> bool {
        if let Some(t) = tryte_from_char(c) {
            let t0 = (t % 3) as Trit;
            let t1 = ((t / 3) % 3) as Trit;
            let t2 = (t / 9) as Trit;
            let ts = [t0, t1, t2];

            for k in self.size_min(3)..3 {
                if 0 != ts[k] { return false; }
            }

            self.put_trits(&ts[0..self.size_min(3)]);
            true
        } else {
            false
        }
    }
    pub fn from_str(mut self, s: &str) -> bool {
        for c in s.chars() {
            if !self.put_char(c) { return false; }
            self = self.drop_min(3);
        }
        true
    }

    pub fn inc(self) -> bool {
        while !self.is_empty() {
            let t = (1 + self.as_const().get_trit()) % 3;
            self.put_trit(t);
            if 0 != t { return true; }
        }
        false
    }

    pub fn set_trit(mut self, t: Trit) {
        assert!(t < 3);
        while !self.is_empty() {
            self.put_trit(t);
            self = self.drop(1);
        }
    }
    pub fn set_zero(self) {
        TW::unsafe_set_zero(self.size(), self.d, self.p);
    }

    pub fn is_same(self, x: Self) -> bool {
        unsafe {
            true
                && self.p.add(self.d / TW::SIZE) == x.p.add(self.d / TW::SIZE)
                && (self.d % TW::SIZE) == (x.d % TW::SIZE)
        }
        //self.p == x.p && self.d == x.d //&& self.n == x.n
    }
    pub fn is_overlapped(self, x: Self) -> bool {
        unsafe {
            let begin = self.p.add(self.d / TW::SIZE);
            let end = self.p.add((self.n + TW::SIZE - 1) / TW::SIZE);
            let x_begin = x.p.add(x.d / TW::SIZE);
            let x_end = x.p.add((x.n + TW::SIZE - 1) / TW::SIZE);
            !(x_end <= begin || end <= x_begin)
        }
    }
    #[inline]
    pub fn is_empty(self) -> bool {
        self.n == self.d
    }
    #[inline]
    pub fn total_size(self) -> usize {
        self.n
    }
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        std::cmp::min(self.size(), s)
    }
    #[inline]
    pub fn take(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.d + n,
            d: self.d,
            p: self.p,
        }
    }
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        Self {
            n: std::cmp::min(self.n, self.d + n),
            d: self.d,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.n,
            d: self.d + n,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        Self {
            n: self.n,
            d: std::cmp::min(self.n, self.d + n),
            p: self.p,
        }
    }
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        assert!(self.d >= n);
        Self {
            n: self.n,
            d: self.d - n,
            p: self.p,
        }
    }
    #[inline]
    pub fn pickup_all(self) -> Self {
        Self {
            n: self.n,
            d: 0,
            p: self.p,
        }
    }
    #[inline]
    pub fn drop_all(self) -> Self {
        Self {
            n: self.n,
            d: self.n,
            p: self.p,
        }
    }
    #[inline]
    pub fn dropped(self) -> Self {
        Self {
            n: self.d,
            d: 0,
            p: self.p,
        }
    }
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let t = self.take(n);
        *self = self.drop(n);
        t
    }

    pub fn swap_add(self, s: Self) {
        assert!(self.size() == s.size());
        TW::unsafe_swap_add(self.size(), self.d, self.p, s.d, s.p);
    }
    pub fn swap_add_min(self, s: Self) -> usize {
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).swap_add(s.take(n));
        n
    }
    pub fn swap_sub(self, s: Self) {
        assert!(self.size() == s.size());
        TW::unsafe_swap_sub(self.size(), self.d, self.p, s.d, s.p);
    }
    pub fn swap_sub_min(self, s: Self) -> usize {
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).swap_sub(s.take(n));
        n
    }
}

impl<TW> PartialEq for TritConstSlice<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && TW::unsafe_eq(self.size(), self.d, self.p, other.d, other.p)
    }
}
impl<TW> Eq for TritConstSlice<TW> where TW: TritWord + Copy {}

impl<TW> PartialEq for TritMutSlice<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.as_const() == other.as_const()
    }
}
impl<TW> Eq for TritMutSlice<TW> where TW: TritWord + Copy {}

impl<TW> PartialEq for Trits<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}
impl<TW> Eq for Trits<TW> where TW: TritWord + Copy {}

impl<TW> Display for TritConstSlice<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let mut this = *self;
        while !this.is_empty() {
            if let Err(e) = f.write_char(this.get_char()) {
                return Err(e);
            }
            this = this.drop_min(3);
        }
        Ok(())
    }
}

impl<TW> Display for TritMutSlice<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.as_const().fmt(f)
    }
}

#[cfg(test)]
mod test_trits {
    use super::*;

    #[test]
    fn test_mods() {
        let r: i32 = 3*19683;
        let m1 = 3;
        let m3 = 27;
        let m9 = 19683;
        for t in -r .. r {
            let (r1, q1) = mods1(t);
            assert!(r1 as i32 + q1 * m1 == t);
            let (r3, q3) = mods3(t);
            assert!(r3 as i32 + q3 * m3 == t);
            let (r9, q9) = mods9(t);
            assert!(r9 as i32 + q9 * m9 == t);
        }
    }

    #[test]
    fn test_str() {
        let mut ts = Trits::<Trit>::zero(15);
        assert!(ts.mut_slice().from_str("9ANMZ"));
        let s = ts.slice().to_str();
        assert_eq!(s, "9ANMZ");
    }
}
