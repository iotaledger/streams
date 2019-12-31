use std::fmt;
use std::hash::{Hash, Hasher};

/// Unsigned trit type with values in range 0..2. Used by Troika implementation.
pub type Trit = u8; //0..2
/// Unsigned tryte type.
pub type Tryte = u8; //0..26

/// Signed trit type: -1..1.
pub type Trint1 = i8;
pub const MAX_TRINT1: Trint1 = 1;
pub const MIN_TRINT1: Trint1 = -MAX_TRINT1;

/// Signed tryte type: -13..13.
pub type Trint3 = i8;
pub const MAX_TRINT3: Trint3 = 13;
pub const MIN_TRINT3: Trint3 = -MAX_TRINT3;

/// Signed 6-trit integer type.
pub type Trint6 = i16;
pub const MAX_TRINT6: Trint6 = 364;
pub const MIN_TRINT6: Trint6 = -MAX_TRINT6;

/// Signed 9-trit integer type.
pub type Trint9 = i16;
pub const MAX_TRINT9: Trint9 = 9841;
pub const MIN_TRINT9: Trint9 = -MAX_TRINT9;

/// Signed 18-trit integer type.
pub type Trint18 = i32;
pub const MAX_TRINT18: Trint18 = 193710244;
pub const MIN_TRINT18: Trint18 = -MAX_TRINT18;

/// `std::i32::MIN + (m-1)/2 < t && t < std::i32::MAX - (m-1)/2`.
fn mods_i32(t: i32, m: i32) -> (i32, i32) {
    //TODO: Simplify to avoid triple division (third division is in `q`).
    let r = (((t % m) + m + (m-1)/2) % m) - (m-1)/2;
    //TODO: Deal with overflows of `i32` type.
    let q = (t - r) / m;
    (r, q)
}

/// Remainder `r` and quotient `q` of `t` `mods 3^1` where
/// `t == q * 3^1 + r` and `-1 <= r <= 1`.
pub fn mods1_usize(t: usize) -> (Trint1, usize) {
    let mut r = (t % 3) as Trint1;
    let mut q = t / 3;
    if r == 2 {
        r = -1;
        q += 1;
    }
    (r, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3_usize(t: usize) -> (Trint3, usize) {
    let mut r = (t % 27) as Trint3;
    let mut q = t / 27;
    if 13 < r {
        r -= 27;
        q += 1;
    }
    (r, q)
}

/// Remainder `r` and quotient `q` of `t` `mods 3^1` where
/// `t == q * 3^1 + r` and `-1 <= r <= 1`.
pub fn mods1(t: i32) -> (Trint1, i32) {
    let (r, q) = mods_i32(t, 3);
    (r as Trint1, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3(t: i32) -> (Trint3, i32) {
    let (r, q) = mods_i32(t, 27);
    (r as Trint3, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^9` where
/// `t == q * 3^9 + r` and `-9841 <= r <= 9841`.
pub fn mods9(t: i32) -> (Trint9, i32) {
    let (r, q) = mods_i32(t, 19683);
    (r as Trint9, q)
}

/// Convert tryte to char:
/// - `0 => '9'`;
/// - `1 => 'A'`;
/// - `13 => 'M'`;
/// - `14 => 'N'`;
/// - `26 => 'Z'`.
pub fn tryte_to_char(t: Tryte) -> char {
    debug_assert!(t < 27);
    if t == 0 {
        '9'
    } else {
        (t - 1 + 'A' as Tryte) as char
    }
}
/// Try convert char to tryte, returns `None` for invalid input char.
///
/// ```rust
/// use iota_mam::trits::*;
/// for t in 0 as Tryte .. 26 {
///     assert_eq!(Some(t), tryte_from_char(tryte_to_char(t)));
/// }
/// ```
pub fn tryte_from_char(c: char) -> Option<Tryte> {
    if 'A' <= c && c <= 'Z' {
        Some(c as Tryte - 'A' as Tryte + 1)
    } else if '9' == c {
        Some(0)
    } else {
        None
    }
}

/// Convert tryte (which is unsigned) to trint3 (which is signed).
pub fn tryte_to_trint3(t: Tryte) -> Trint3 {
    debug_assert!(t < 27);
    if 13 < t {
        (t as Trint3) - 27
    } else {
        t as Trint3
    }
}
/// Convert tryte (which is unsigned) from trint3 (which is signed).
///
/// ```rust
/// use iota_mam::trits::*;
/// for t in 0 .. 26 {
///     assert_eq!(t, tryte_from_trint3(tryte_to_trint3(t)));
/// }
/// ```
pub fn tryte_from_trint3(t: Trint3) -> Tryte {
    debug_assert!(-13 <= t && t <= 13);
    if t < 0 {
        (t + 27) as Tryte
    } else {
        t as Tryte
    }
}

/// Convert trint3 to char.
///
/// ```rust
/// use iota_mam::trits::*;
/// for t in -13 .. 13 {
///     assert_eq!(tryte_to_char(tryte_from_trint3(t)), trint3_to_char(t));
/// }
/// ```
pub fn trint3_to_char(t: Trint3) -> char {
    debug_assert!(-13 <= t && t <= 13);
    if t < 0 {
        ((t + 26 + 'A' as Trint3) as u8) as char
    } else if t > 0 {
        ((t - 1 + 'A' as Trint3) as u8) as char
    } else {
        '9'
    }
}
/// Convert trint3 from char.
///
/// ```rust
/// use iota_mam::trits::*;
/// let s = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// for c in s.chars() {
///     assert_eq!(tryte_from_char(c).map(tryte_to_trint3), trint3_from_char(c));
/// }
/// ```
pub fn trint3_from_char(c: char) -> Option<Trint3> {
    if 'A' <= c && c <= 'M' {
        Some(c as Trint3 - 'A' as Trint3 + 1)
    } else if 'N' <= c && c <= 'Z' {
        Some(c as Trint3 - 'A' as Trint3 - 26)
    } else if '9' == c {
        Some(0)
    } else {
        None
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

/// Container for trits using a certain trit encoding.
/// Access to the individual trits should be performed via `TritConstSliceT` and `TritMutSliceT` types.
#[derive(Clone)]
pub struct TritsT<TW> {
    n: usize,
    buf: std::vec::Vec<TW>,
}

impl<TW> TritsT<TW> where TW: TritWord + Copy {
    /// Create a container filled with `n` zero trits.
    pub fn zero(n: usize) -> Self {
        Self {
            n: n,
            buf: vec![TW::zero(); (n + TW::SIZE - 1) / TW::SIZE]
        }
    }
    /// Create a container with `n` trits and cycle `t` to fill it.
    pub fn cycle_trits(n: usize, t: &Self) -> Self {
        let mut x = Self::zero(n);
        x.mut_slice().cycle(t.slice());
        x
    }
    /// Create a container with `n` trits and cycle `s` to fill it.
    pub fn cycle_str(n: usize, s: &str) -> Self {
        //Self::from_str(s).map_or(Self::zero(n), |t| Self::cycle_trits(n, &t))
        Self::cycle_trits(n, &Self::from_str(s).unwrap_or(Self::zero(0)))
    }
    /// Try parse and create trits from ASCII-encoded tryte string `s`.
    pub fn from_str(s: &str) -> Option<Self> {
        let mut t = Self::zero(3 * s.len());
        if t.mut_slice().from_str(s) {
            Some(t)
        } else {
            None
        }
    }
    /// ASCII convert trytes.
    pub fn to_str(&self) -> String {
        self.slice().to_str()
    }
    /// Create container and initialize trits by copying from slice `t`.
    pub fn from_slice(t: TritConstSliceT<TW>) -> Self {
        let mut x = Self::zero(t.size());
        t.copy(x.mut_slice());
        x
    }
    /// Return a constant slice object to the trits in the container.
    pub fn slice(&self) -> TritConstSliceT<TW> {
        TritConstSliceT::<TW>::from_trits(self)
    }
    /// Return a mutable slice object to the trits in the container.
    pub fn mut_slice(&mut self) -> TritMutSliceT<TW> {
        TritMutSliceT::<TW>::from_mut_trits(self)
    }
    /// Return internal buffer length, ie. the number of trit words.
    pub fn buf_len(&self) -> usize {
        self.buf.len()
    }
    /// Return the number of trits in the container.
    pub fn size(&self) -> usize {
        self.n
    }
    /// Is container empty?
    pub fn is_empty(&self) -> bool {
        0 == self.n
    }
}

/// Slice to an array of trit words providing constant access to the trits.
///
/// Slice can be thought of as an offset `d` within range `[0..n)` referred as total range.
/// `[0..d)` is dropped range, `[d..n)` is current (or available) range.
/// Trit accessor functions work with the current range.
///
/// NB: The type is implemented via raw pointers and is thus somewhat unsafe.
/// Objects of this type don't own trits they point to and are usually short-lived.
#[derive(Copy, Clone)]
pub struct TritConstSliceT<TW> {
    n: usize, // size in trits
    d: usize, // offset in trits; d < n
    p: *const TW, // slice
}

/// Slice to an array of trit words providing mutable access to the trits.
///
/// Slice can be thought of as an offset `d` within range `[0..n)` referred as total range.
/// `[0..d)` is dropped range, `[d..n)` is current (or available) range.
/// Trit accessor functions work with the current range.
///
/// NB: The type is implemented via raw pointers and is thus somewhat unsafe.
/// Objects of this type don't own trits they point to and are usually short-lived.
#[derive(Copy, Clone)]
pub struct TritMutSliceT<TW> {
    n: usize, // size in trits
    d: usize, // offset in trits; d < n
    p: *mut TW, // slice
}

impl<TW> TritConstSliceT<TW> where TW: TritWord + Copy {
    /// Create container initialized with the slice.
    pub fn clone_trits(self) -> TritsT<TW>
    {
        let mut t = TritsT::<TW>::zero(self.size());
        self.copy(t.mut_slice());
        t
    }
    /// Create slice pointing to the start of the container `t`.
    pub fn from_trits(t: &TritsT<TW>) -> Self {
        Self {
            n: t.size(),
            d: 0,
            p: t.buf.as_ptr(),
        }
    }
    /// Create slice of `n` trits pointing to the array slice `t`.
    pub fn from_slice(n: usize, t: &[TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self {
            n: n,
            d: 0,
            p: t.as_ptr(),
        }
    }

    pub fn get_trit(self) -> Trit {
        debug_assert!(!self.is_empty());
        TW::get_trit(self.d, self.p)
    }
    pub fn get_trits(mut self, trits: &mut [Trit]) {
        debug_assert!(self.size() >= trits.len());
        for t in trits {
            *t = self.get_trit();
            self = self.drop(1);
        }
    }
    pub fn get_tryte(self) -> Tryte {
        debug_assert!(self.d + 3 <= self.n);
        TW::get_tryte(self.d, self.p)
    }
    pub fn get1s(mut self, t1s: &mut [Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        for t in t1s {
            *t = self.get1();
            self = self.drop(1);
        }
    }
    pub fn get1(self) -> Trint1 {
        debug_assert!(self.d + 1 <= self.n);
        TW::get1(self.d, self.p)
    }
    pub fn get3(self) -> Trint3 {
        debug_assert!(self.d + 3 <= self.n);
        TW::get3(self.d, self.p)
    }
    pub fn get6(self) -> Trint6 {
        debug_assert!(self.d + 6 <= self.n);
        TW::get6(self.d, self.p)
    }
    pub fn get9(self) -> Trint9 {
        debug_assert!(self.d + 9 <= self.n);
        TW::get9(self.d, self.p)
    }
    pub fn get18(self) -> Trint18 {
        debug_assert!(self.d + 18 <= self.n);
        TW::get18(self.d, self.p)
    }
    /// Get a tryte at the current offset and ASCII-convert it as char.
    pub fn get_char(self) -> char {
        /*
        let mut ts: [Trit; 3] = [0; 3];
        self.get_trits(&mut ts[0..self.size_min(3)]);
        let t = 0 + 1 * (ts[0] as Tryte) + 3 * (ts[1] as Tryte) + 9 * (ts[2] as Tryte);
        tryte_to_char(t)
         */
        let mut ts: [Trint1; 3] = [0; 3];
        self.get1s(&mut ts[0..self.size_min(3)]);
        let t = 0 + 1 * (ts[0] as Trint3) + 3 * (ts[1] as Trint3) + 9 * (ts[2] as Trint3);
        trint3_to_char(t)
    }
    /// ASCII encode trytes at the current offset.
    /// The last incomplete tryte if any is padded with zero trits.
    pub fn to_str(mut self) -> String {
        let mut s = String::with_capacity((self.size() + 2) / 3);
        while !self.is_empty() {
            s.push(self.get_char());
            self = self.drop_min(3);
        }
        s
    }

    /// Check whether `x` slice points to the same trit in memory as `self`.
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
    /// Size of total range.
    #[inline]
    pub fn total_size(self) -> usize {
        self.n
    }
    /// Size of dropped range, ie. the number of trits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }
    /// Size of current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }
    /// Size of current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }
    /// Size of current range but no more than `s`.
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
    pub fn split_at(self, n: usize) -> (Self, Self) {
        debug_assert!(self.n >= self.d + n);
        (Self {
            n: self.d + n,
            d: self.d,
            p: self.p,
        }, Self {
            n: self.n,
            d: self.d + n,
            p: self.p,
        })
    }
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let m = std::cmp::min(self.n, self.d + n);
        (Self {
            n: m,
            d: self.d,
            p: self.p,
        }, Self {
            n: self.n,
            d: m,
            p: self.p,
        })
    }
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        debug_assert!(self.d >= n);
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
    #[inline]
    pub fn diff(self, s: Self) -> Self {
        debug_assert!(self.p == s.p && s.d <= self.d && self.d <= s.n);
        Self {
            n: self.d, // std::cmp::max(self.d, s.d),
            d: s.d, // std::cmp::min(self.d, s.d),
            p: self.p,
        }
    }

    pub fn copy(self, to: TritMutSliceT<TW>) {
        debug_assert!(self.size() == to.size());
        //TODO: is_same(to) || !is_overlapped(to)
        TW::unsafe_copy(self.size(), self.d, self.p, to.d, to.p);
    }
    pub fn copy_min(self, to: TritMutSliceT<TW>) -> usize {
        let n = std::cmp::min(self.size(), to.size());
        self.take(n).copy(to.take(n));
        n
    }

    pub fn copy_add(self, s: TritMutSliceT<TW>, y: TritMutSliceT<TW>) {
        debug_assert!(self.size() == y.size());
        debug_assert!(self.size() == s.size());
        TW::unsafe_copy_add(self.size(), self.d, self.p, s.d, s.p, y.d, y.p);
    }
    pub fn copy_add_min(self, s: TritMutSliceT<TW>, y: TritMutSliceT<TW>) -> usize {
        debug_assert!(self.size() == y.size());
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).copy_add(s.take(n), y.take(n));
        n
    }
    pub fn copy_sub(self, s: TritMutSliceT<TW>, y: TritMutSliceT<TW>) {
        debug_assert!(self.size() == y.size());
        debug_assert!(self.size() == s.size());
        TW::unsafe_copy_sub(self.size(), self.d, self.p, s.d, s.p, y.d, y.p);
    }
    pub fn copy_sub_min(self, s: TritMutSliceT<TW>, y: TritMutSliceT<TW>) -> usize {
        debug_assert!(self.size() == y.size());
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).copy_sub(s.take(n), y.take(n));
        n
    }
}

impl<TW> TritMutSliceT<TW> where TW: TritWord + Copy {
    /// Convert to const slice.
    pub fn as_const(self) -> TritConstSliceT<TW> {
        TritConstSliceT::<TW> {
            n: self.n,
            d: self.d,
            p: self.p,
        }
    }
    /// Create slice pointing to the start of the container `t`.
    pub fn from_mut_trits(t: &mut TritsT<TW>) -> Self {
        Self {
            n: t.size(),
            d: 0,
            p: t.buf.as_mut_ptr(),
        }
    }
    /// Create slice of `n` trits pointing to the array slice `t`.
    pub fn from_mut_slice(n: usize, t: &mut [TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self {
            n: n,
            d: 0,
            p: t.as_mut_ptr(),
        }
    }
    /// Cycle slice `ts` to fill `self`.
    pub fn cycle(mut self, ts: TritConstSliceT<TW>) {
        if !ts.is_empty() {
            while !self.is_empty() {
                let n = ts.copy_min(self);
                self = self.drop(n);
            }
        }
    }

    pub fn put_trit(self, t: Trit) {
        debug_assert!(!self.is_empty());
        TW::put_trit(self.d, self.p, t)
    }
    pub fn put_trits(mut self, trits: &[Trit]) {
        debug_assert!(self.size() >= trits.len());
        for t in trits {
            self.put_trit(*t);
            self = self.drop(1);
        }
    }
    pub fn put_tryte(self, t: Tryte) {
        debug_assert!(self.d + 3 <= self.n);
        TW::put_tryte(self.d, self.p, t)
    }
    pub fn put1s(mut self, t1s: &[Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        for t in t1s {
            self.put1(*t);
            self = self.drop(1);
        }
    }
    pub fn put1(self, t: Trint1) {
        debug_assert!(self.d + 1 <= self.n);
        TW::put1(self.d, self.p, t)
    }
    pub fn put3(self, t: Trint3) {
        debug_assert!(self.d + 3 <= self.n);
        TW::put3(self.d, self.p, t)
    }
    pub fn put6(self, t: Trint6) {
        debug_assert!(self.d + 6 <= self.n);
        TW::put6(self.d, self.p, t)
    }
    pub fn put9(self, t: Trint9) {
        debug_assert!(self.d + 9 <= self.n);
        TW::put9(self.d, self.p, t)
    }
    pub fn put18(self, t: Trint18) {
        debug_assert!(self.d + 18 <= self.n);
        TW::put18(self.d, self.p, t)
    }
    /// Try to ASCII-convert a char `c` to a tryte and put it at the current offset.
    pub fn put_char(self, c: char) -> bool {
        /* // Conversion via unsigned Tryte does not respect signedness of internal trits representation.
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
         */

        if let Some(t) = trint3_from_char(c) {
            let (t0, q0) = mods1(t as i32);
            let (t1, q1) = mods1(q0 as i32);
            let (t2, _) = mods1(q1 as i32);
            let ts = [t0, t1, t2];

            for k in self.size_min(3)..3 {
                if 0 != ts[k] { return false; }
            }

            self.put1s(&ts[0..self.size_min(3)]);
            true
        } else {
            false
        }
    }
    /// Try to ASCII-convert string `s` to trytes and put them at the current offset.
    /// If the length of `s` exceeds the size of the slice the remaining trits of `s` must be zero.
    pub fn from_str(mut self, s: &str) -> bool {
        for c in s.chars() {
            if !self.put_char(c) { return false; }
            self = self.drop_min(3);
        }
        true
    }

    /// Increment trits in the range `[d..n)` as integer.
    pub fn inc(self) -> bool {
        while !self.is_empty() {
            let t = (1 + self.as_const().get_trit()) % 3;
            self.put_trit(t);
            if 0 != t { return true; }
        }
        false
    }

    pub fn set_trit(mut self, t: Trit) {
        debug_assert!(t < 3);
        while !self.is_empty() {
            self.put_trit(t);
            self = self.drop(1);
        }
    }
    pub fn set_zero(self) {
        TW::unsafe_set_zero(self.size(), self.d, self.p);
    }

    /// Check whether `x` slice points to the same trit in memory as `self`.
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
    /// Size of total range.
    #[inline]
    pub fn total_size(self) -> usize {
        self.n
    }
    /// Size of dropped range, ie. the number of trits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }
    /// Size of current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }
    /// Size of current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }
    /// Size of current range but no more than `s`.
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
        debug_assert!(self.d >= n);
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
    #[inline]
    pub fn diff(self, s: Self) -> Self {
        debug_assert!(self.p == s.p && s.d <= self.d && self.d <= s.n);
        Self {
            n: self.d, // std::cmp::max(self.d, s.d),
            d: s.d, // std::cmp::min(self.d, s.d),
            p: self.p,
        }
    }

    pub fn swap_add(self, s: Self) {
        debug_assert!(self.size() == s.size());
        TW::unsafe_swap_add(self.size(), self.d, self.p, s.d, s.p);
    }
    pub fn swap_add_min(self, s: Self) -> usize {
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).swap_add(s.take(n));
        n
    }
    pub fn swap_sub(self, s: Self) {
        debug_assert!(self.size() == s.size());
        TW::unsafe_swap_sub(self.size(), self.d, self.p, s.d, s.p);
    }
    pub fn swap_sub_min(self, s: Self) -> usize {
        let n = std::cmp::min(self.size(), s.size());
        self.take(n).swap_sub(s.take(n));
        n
    }
}

impl<TW> PartialEq for TritConstSliceT<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && TW::unsafe_eq(self.size(), self.d, self.p, other.d, other.p)
    }
}
impl<TW> Eq for TritConstSliceT<TW> where TW: TritWord + Copy {}

impl<TW> PartialEq for TritMutSliceT<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.as_const() == other.as_const()
    }
}
impl<TW> Eq for TritMutSliceT<TW> where TW: TritWord + Copy {}

impl<TW> PartialEq for TritsT<TW> where TW: TritWord + Copy {
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}
impl<TW> Eq for TritsT<TW> where TW: TritWord + Copy {}

impl<TW> fmt::Display for TritConstSliceT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write as _;
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

impl<TW> fmt::Debug for TritConstSliceT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{},{:?}):", self.n, self.d, self.p)?;

        write!(f, "[")?;
        for d in 0..self.d {
            let t = TW::get_trit(d, self.p);
            write!(f, "{}", t)?;
        }
        write!(f, "|")?;
        for d in self.d..self.n {
            let t = TW::get_trit(d, self.p);
            write!(f, "{}", t)?;
        }
        write!(f, "]")?;
        write!(f, "")
    }
}

impl<TW> fmt::Display for TritMutSliceT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_const())
    }
}

impl<TW> fmt::Debug for TritMutSliceT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_const())
    }
}

impl<TW> Hash for TritsT<TW> where TW: TritWord + Copy + Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.n.hash(state);
        self.buf.hash(state);
    }
}

impl<TW> fmt::Display for TritsT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.slice().fmt(f)
    }
}

impl<TW> fmt::Debug for TritsT<TW> where TW: TritWord + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.n, self.slice())
    }
}

pub type DefaultTritWord = Trit;
pub type Trits = TritsT<DefaultTritWord>;
pub type TritConstSlice = TritConstSliceT<DefaultTritWord>;
pub type TritMutSlice = TritMutSliceT<DefaultTritWord>;

#[cfg(test)]
mod test {
    use super::*;

    fn mods_i32(t: i32) {
        let m1 = 3;
        let m3 = 27;
        let m9 = 19683;

        let (r1, q1) = mods1(t);
        assert_eq!(t, r1 as i32 + q1 * m1);
        let (r3, q3) = mods3(t);
        assert_eq!(t, r3 as i32 + q3 * m3);
        let (r9, q9) = mods9(t);
        assert_eq!(t, r9 as i32 + q9 * m9);
    }
    fn mods_usize(t: usize) {
        let (ru, qu) = mods1_usize(t);
        let tt = if ru < 0 {
            qu * 3 - (-ru) as usize
        } else {
            qu * 3 + ru as usize
        };
        assert_eq!(t, tt);
    }

    #[test]
    fn mods() {
        let r: i32 = 3*19683;
        for t in -r .. r {
            mods_i32(t);
        }
        /*
        mods_i32(std::i32::MAX);
        mods_i32(std::i32::MAX-1);
        mods_i32(std::i32::MAX-2);
        mods_i32(std::i32::MIN+2);
        mods_i32(std::i32::MIN+1);
        mods_i32(std::i32::MIN);
         */

        for t in 0_usize .. 100_usize {
            mods_usize(t);
        }
        /*
        mods_usize(std::usize::MAX);
        mods_usize(std::usize::MAX-1);
        mods_usize(std::usize::MAX-2);
         */
    }

    #[test]
    fn char() {
        assert_eq!(Some(0), tryte_from_char('9'));
        assert_eq!(Some(1), tryte_from_char('A'));
        assert_eq!(Some(2), tryte_from_char('B'));
        assert_eq!(Some(13), tryte_from_char('M'));
        assert_eq!(Some(14), tryte_from_char('N'));
        assert_eq!(Some(26), tryte_from_char('Z'));

        assert_eq!(Some(0), trint3_from_char('9'));
        assert_eq!(Some(1), trint3_from_char('A'));
        assert_eq!(Some(2), trint3_from_char('B'));
        assert_eq!(Some(13), trint3_from_char('M'));
        assert_eq!(Some(-13), trint3_from_char('N'));
        assert_eq!(Some(-1), trint3_from_char('Z'));
    }

    #[test]
    fn str() {
        let mut ts = Trits::zero(15);
        assert!(ts.mut_slice().from_str("9ANMZ"));
        let s = ts.slice().to_str();
        assert_eq!(s, "9ANMZ");

        let mut trits = [0; 15];
        ts.slice().get_trits(&mut trits);
        assert_eq!(trits, [0,0,0, 1,0,0, 2,2,2, 1,1,1, 2,0,0]);

        assert_eq!(0, Trits::from_str("9").unwrap().slice().get3());
        assert_eq!(1, Trits::from_str("A").unwrap().slice().get3());
        assert_eq!(2, Trits::from_str("B").unwrap().slice().get3());
        assert_eq!(13, Trits::from_str("M").unwrap().slice().get3());
        assert_eq!(-13, Trits::from_str("N").unwrap().slice().get3());
        assert_eq!(-1, Trits::from_str("Z").unwrap().slice().get3());

        assert_eq!("AAA", Trits::cycle_str(9, "A").to_str());
        assert_eq!("AAAA", Trits::cycle_str(10, "A").to_str());
    }
}
