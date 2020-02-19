use std::convert::TryFrom;
use std::fmt;
use std::hash;

use super::{defs::*, trits::*, word::*};

#[derive(Copy, Clone, Debug)]
struct SliceRange {
    n: usize,
    d: usize,
}

impl SliceRange {
    fn new(n: usize, d: usize) -> Self {
        Self { n, d }
    }

    /// Is the range empty?
    #[inline]
    pub fn is_empty(self) -> bool {
        self.n == self.d
    }

    /// Size of the total range.
    #[inline]
    pub fn total_size(self) -> usize {
        self.n
    }

    /// Size of the dropped range, ie. the number of trits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }

    /// Size of the current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }

    /// Size of the current range, ie. the number of trits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }

    /// Size of the current range but no more than `s`.
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        std::cmp::min(self.size(), s)
    }

    /// Take `n` trits from the current range.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.d + n,
            d: self.d,
        }
    }

    /// Take no more than `n` trits from the current range.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        Self {
            n: std::cmp::min(self.n, self.d + n),
            d: self.d,
        }
    }

    /// Drop `n` trits from the current range.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        debug_assert!(self.n >= self.d + n);
        Self {
            n: self.n,
            d: self.d + n,
        }
    }

    /// Drop no more than `n` trits from the current range.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        Self {
            n: self.n,
            d: std::cmp::min(self.n, self.d + n),
        }
    }

    /// Take and drop `n` trits from the current range.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        debug_assert!(self.n >= self.d + n);
        (
            Self {
                n: self.d + n,
                d: self.d,
            },
            Self {
                n: self.n,
                d: self.d + n,
            },
        )
    }

    /// Take and drop no more than `n` trits from the current range.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let m = std::cmp::min(self.n, self.d + n);
        (Self { n: m, d: self.d }, Self { n: self.n, d: m })
    }

    /// Pickup `n` trits from the dropped range.
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        debug_assert!(self.d >= n);
        Self {
            n: self.n,
            d: self.d - n,
        }
    }

    /// Pickup all the dropped trits.
    #[inline]
    pub fn pickup_all(self) -> Self {
        Self { n: self.n, d: 0 }
    }

    /// Drop all the current trits.
    #[inline]
    pub fn drop_all(self) -> Self {
        Self {
            n: self.n,
            d: self.n,
        }
    }

    /// The dropped range.
    #[inline]
    pub fn dropped(self) -> Self {
        Self { n: self.d, d: 0 }
    }

    /// Difference between the current advanced range and `s` range.
    #[inline]
    pub fn diff(self, s: Self) -> Self {
        debug_assert!(s.d <= self.d && self.d <= s.n);
        // let n = std::cmp::max(self.d, s.d);
        // let d = std::cmp::min(self.d, s.d);
        Self { n: self.d, d: s.d }
    }
}

#[derive(Copy, Clone)]
pub struct TritSliceT<'a, TW: 'a> {
    r: SliceRange,
    p: *const TW,
    phantom: std::marker::PhantomData<&'a TW>,
}

impl<'a, TW: 'a> TritSliceT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    /// Create slice of size `n` pointing to `p`.
    pub fn from_raw_ptr(n: usize, p: *const TW) -> Self {
        Self {
            r: SliceRange::new(n, 0),
            p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Create slice of `n` trits pointing to the array slice `t`.
    pub fn from_slice(n: usize, t: &'a [TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self::from_raw_ptr(n, t.as_ptr())
    }

    /// Create slice pointing to the start of the container `t`.
    pub fn from_trits(t: &'a TritsT<TW>) -> Self {
        t.slice()
    }

    /// Create container initialized with the slice.
    pub fn clone_trits(self) -> TritsT<TW> {
        TritsT::from_slice(self)
    }

    pub fn get_trits(self, trits: &mut [Trit]) {
        debug_assert!(self.size() >= trits.len());
        TW::unsafe_to_trits(self.size(), self.r.d, self.p, trits.as_mut_ptr() as *mut u8);
        /*
        for t in trits {
            *t = self.get_trit();
            self = self.drop(1);
        }
         */
    }

    /// Check whether `x` slice points to the same trit in memory as `self`.
    pub fn is_same(self, x: Self) -> bool {
        unsafe {
            true && self.p.add(self.r.d / TW::SIZE) == x.p.add(self.r.d / TW::SIZE)
                && (self.r.d % TW::SIZE) == (x.r.d % TW::SIZE)
        }
        //self.p == x.p && self.r.d == x.r.d //&& self.r.n == x.r.n
    }
    pub fn is_overlapped(self, x: Self) -> bool {
        unsafe {
            let begin = self.p.add(self.r.d / TW::SIZE);
            let end = self.p.add((self.r.n + TW::SIZE - 1) / TW::SIZE);
            let x_begin = x.p.add(x.r.d / TW::SIZE);
            let x_end = x.p.add((x.r.n + TW::SIZE - 1) / TW::SIZE);
            !(x_end <= begin || end <= x_begin)
        }
    }

    /// Is the slice empty?
    #[inline]
    pub fn is_empty(self) -> bool {
        self.r.is_empty()
    }

    /// The total size of the slice.
    #[inline]
    pub fn total_size(self) -> usize {
        self.r.total_size()
    }

    /// Size of the dropped slice, ie. the number of trits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.r.dropped_size()
    }

    /// Size of the current slice, ie. the number of trits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        self.r.avail_size()
    }

    /// Size of the current slice, ie. the number of trits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.r.size()
    }

    /// Size of the current slice but no more than `s`.
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        self.r.size_min(s)
    }

    fn with_range(self, r: SliceRange) -> Self {
        Self {
            r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Take `n` trits from the current slice.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        self.with_range(self.r.take(n))
    }

    /// Take no more than `n` trits from the current slice.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        self.with_range(self.r.take_min(n))
    }

    /// Drop `n` trits from the current slice.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        self.with_range(self.r.drop(n))
    }

    /// Drop no more than `n` trits from the current slice.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        self.with_range(self.r.drop_min(n))
    }

    /// Take and drop `n` trits from the current slice.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        let (t, d) = self.r.split_at(n);
        (self.with_range(t), self.with_range(d))
    }

    /// Take and drop no more than `n` trits from the current range.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let (t, d) = self.r.split_at_min(n);
        (self.with_range(t), self.with_range(d))
    }

    /// Pickup `n` trits from the dropped slice.
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        self.with_range(self.r.pickup(n))
    }

    /// Pickup all the dropped trits.
    #[inline]
    pub fn pickup_all(self) -> Self {
        self.with_range(self.r.pickup_all())
    }

    /// Drop all the current trits.
    #[inline]
    pub fn drop_all(self) -> Self {
        self.with_range(self.r.drop_all())
    }

    /// The dropped slice.
    #[inline]
    pub fn dropped(self) -> Self {
        self.with_range(self.r.dropped())
    }

    /// Advance the current slice by `n` trits.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let t = self.take(n);
        *self = self.drop(n);
        t
    }

    /// Difference between the current advanced slice and `s` slice.
    #[inline]
    pub fn diff(self, s: Self) -> Self {
        debug_assert_eq!(self.p, s.p);
        self.with_range(self.r.diff(s.r))
    }

    pub fn chunks(mut self, s: usize) -> Vec<TritsT<TW>> {
        assert!(s != 0);
        let n = (self.size() + s - 1) / s;
        let mut v = Vec::with_capacity(n);
        while !self.is_empty() {
            v.push(self.take_min(s).clone_trits());
            self = self.drop_min(s);
        }
        v
    }

    pub fn eq(self, other: Self) -> bool {
        debug_assert_eq!(self.size(), other.size());
        TW::unsafe_eq(self.size(), self.r.d, self.p, other.r.d, other.p)
    }
    pub fn eq_min(self, other: Self) -> (bool, usize) {
        let n = std::cmp::min(self.size(), other.size());
        (TW::unsafe_eq(n, self.r.d, self.p, other.r.d, other.p), n)
    }

    pub fn copy(self, to: TritSliceMutT<'a, TW>) {
        debug_assert_eq!(self.size(), to.size());
        //TODO: is_same(to) || !is_overlapped(to)
        TW::unsafe_copy(self.size(), self.r.d, self.p, to.r.d, to.p);
    }
    pub fn copy_min(self, to: TritSliceMutT<'a, TW>) -> usize {
        let x = self.take_min(to.size());
        let n = x.size();
        x.copy(to.take(n));
        n
    }
}

impl<'a, TW: 'a> TritSliceT<'a, TW>
where
    TW: TritWord + Copy,
{
    pub fn get_trit(self) -> Trit {
        debug_assert!(!self.is_empty());
        TW::get_trit(self.r.d, self.p)
    }
    pub fn get_tryte(self) -> Tryte {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::get_tryte(self.r.d, self.p)
    }
    pub fn get1s(mut self, t1s: &mut [Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        for t in t1s {
            *t = self.get1();
            self = self.drop(1);
        }
    }
    pub fn get1(self) -> Trint1 {
        debug_assert!(self.r.d < self.r.n);
        TW::get1(self.r.d, self.p)
    }
    pub fn get3(self) -> Trint3 {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::get3(self.r.d, self.p)
    }
    pub fn get6(self) -> Trint6 {
        debug_assert!(self.r.d + 6 <= self.r.n);
        TW::get6(self.r.d, self.p)
    }
    pub fn get9(self) -> Trint9 {
        debug_assert!(self.r.d + 9 <= self.r.n);
        TW::get9(self.r.d, self.p)
    }
    pub fn get18(self) -> Trint18 {
        debug_assert!(self.r.d + 18 <= self.r.n);
        TW::get18(self.r.d, self.p)
    }
    /// Get a tryte at the current offset and ASCII-convert it as char.
    pub fn get_char(self) -> char {
        // Trits are padded with zeros.
        let mut ts: [Trint1; 3] = [Trint1(0); 3];
        self.get1s(&mut ts[0..self.size_min(3)]);
        char::from(Trint3::from(ts))
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

    pub fn eq_str(mut self, s: &str) -> bool {
        if (self.size() + 2) / 3 != s.len() {
            return false;
        }

        for c in s.chars() {
            if c != self.get_char() {
                return false;
            }
            self = self.drop_min(3);
        }
        true
    }

    pub fn copy_add(self, s: TritSliceMutT<'a, TW>, y: TritSliceMutT<'a, TW>) {
        debug_assert_eq!(self.size(), y.size());
        debug_assert_eq!(self.size(), s.size());
        TW::unsafe_copy_add(self.size(), self.r.d, self.p, s.r.d, s.p, y.r.d, y.p);
    }
    pub fn copy_add_min(self, s: TritSliceMutT<'a, TW>, y: TritSliceMutT<'a, TW>) -> usize {
        debug_assert_eq!(self.size(), y.size());
        let x = self.take_min(s.size());
        let n = x.size();
        x.copy_add(s.take(n), y.take(n));
        n
    }

    pub fn copy_sub(self, s: TritSliceMutT<'a, TW>, y: TritSliceMutT<'a, TW>) {
        debug_assert_eq!(self.size(), y.size());
        debug_assert_eq!(self.size(), s.size());
        TW::unsafe_copy_sub(self.size(), self.r.d, self.p, s.r.d, s.p, y.r.d, y.p);
    }
    pub fn copy_sub_min(self, s: TritSliceMutT<'a, TW>, y: TritSliceMutT<'a, TW>) -> usize {
        debug_assert_eq!(self.size(), y.size());
        let x = self.take_min(s.size());
        let n = x.size();
        x.copy_sub(s.take(n), y.take(n));
        n
    }
}

impl<'a, TW> PartialEq for TritSliceT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && Self::eq(*self, *other)
    }
}
impl<'a, TW> Eq for TritSliceT<'a, TW> where TW: BasicTritWord + Copy {}

impl<'a, TW> hash::Hash for TritSliceT<'a, TW>
where
    TW: BasicTritWord,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        <TW as BasicTritWord>::unsafe_fold_trits(self.r.n, self.r.d, self.p, |t| t.hash(state));
    }
}

impl<'a, TW> fmt::Display for TritSliceT<'a, TW>
where
    TW: TritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write as _;
        let mut this = *self;
        while !this.is_empty() {
            f.write_char(this.get_char())?;
            this = this.drop_min(3);
        }
        Ok(())
    }
}

fn write_trits<TW>(n: usize, dx: usize, x: *const TW, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    TW: BasicTritWord + Copy,
{
    if n == 0 {
        return Ok(());
    }

    unsafe {
        let mut v = vec![0u8; TW::SIZE];
        let rx = dx % TW::SIZE;
        let mut xx = x.add(dx / TW::SIZE);
        let mut nn = n;
        let mut d;

        if rx != 0 {
            d = std::cmp::min(n, TW::SIZE - rx);
            TW::unsafe_word_to_trits(*xx, v.as_mut_ptr());
            for t in v[rx..rx + d].into_iter() {
                write!(f, "{}", t)?;
            }
            nn -= d;
            xx = xx.add(1);
        }

        d = TW::SIZE;
        while nn >= d {
            TW::unsafe_word_to_trits(*xx, v.as_mut_ptr());
            for t in v[..].into_iter() {
                write!(f, "{}", t)?;
            }
            nn -= d;
            xx = xx.add(1);
        }

        if nn > 0 {
            TW::unsafe_word_to_trits(*xx, v.as_mut_ptr());
            for t in v[..nn].into_iter() {
                write!(f, "{}", t)?;
            }
        }

        Ok(())
    }
}

impl<'a, TW> fmt::Debug for TritSliceT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{},{:?}):", self.r.n, self.r.d, self.p)?;

        write!(f, "[")?;
        /*
        for d in 0..self.r.d {
            let t = TW::get_trit(d, self.p);
            write!(f, "{}", t)?;
        }
         */
        write_trits::<TW>(self.r.d, 0, self.p, f)?;
        write!(f, "|")?;
        /*
        for d in self.r.d..self.r.n {
            let t = TW::get_trit(d, self.p);
            write!(f, "{}", t)?;
        }
        */
        write_trits::<TW>(self.r.n - self.r.d, self.r.d, self.p, f)?;
        write!(f, "]")?;
        write!(f, "")
    }
}

#[derive(Copy, Clone)]
pub struct TritSliceMutT<'a, TW: 'a> {
    r: SliceRange,
    p: *mut TW,
    phantom: std::marker::PhantomData<&'a TW>,
}

impl<'a, TW: 'a> TritSliceMutT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    /// Create slice of `n` trits pointing to the array slice `t`.
    pub fn from_raw_ptr(n: usize, p: *mut TW) -> Self {
        Self {
            r: SliceRange::new(n, 0),
            p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Create slice of `n` trits pointing to the array slice `t`.
    pub fn from_slice_mut(n: usize, t: &'a mut [TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self::from_raw_ptr(n, t.as_mut_ptr())
    }

    /// Create slice pointing to the start of the container `t`.
    pub fn from_trits_mut(t: &'a mut TritsT<TW>) -> Self {
        t.slice_mut()
    }

    /// Cycle slice `ts` to fill `self`.
    pub fn cycle(mut self, ts: TritSliceT<'a, TW>) {
        if !ts.is_empty() {
            while !self.is_empty() {
                let n = ts.copy_min(self);
                self = self.drop(n);
            }
        }
    }

    /// Convert to const slice.
    pub fn as_const(self) -> TritSliceT<'a, TW> {
        TritSliceT::<'a, TW> {
            r: self.r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }
    pub fn as_slice<'b>(&'b self) -> TritSliceT<'b, TW> {
        TritSliceT::<'b, TW> {
            r: self.r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn put_trits(self, trits: &[Trit]) {
        debug_assert!(self.size() >= trits.len());
        TW::unsafe_from_trits(self.size(), self.r.d, self.p, trits.as_ptr() as *const u8);
        /*
        for t in trits {
            self.put_trit(*t);
            self = self.drop(1);
        }
         */
    }

    pub fn set_zero(self) {
        TW::unsafe_set_zero(self.size(), self.r.d, self.p);
    }

    /// Check whether `x` slice points to the same trit in memory as `self`.
    pub fn is_same(self, x: Self) -> bool {
        unsafe {
            true && self.p.add(self.r.d / TW::SIZE) == x.p.add(self.r.d / TW::SIZE)
                && (self.r.d % TW::SIZE) == (x.r.d % TW::SIZE)
        }
        //self.p == x.p && self.r.d == x.r.d //&& self.r.n == x.r.n
    }
    pub fn is_overlapped(self, x: Self) -> bool {
        unsafe {
            let begin = self.p.add(self.r.d / TW::SIZE);
            let end = self.p.add((self.r.n + TW::SIZE - 1) / TW::SIZE);
            let x_begin = x.p.add(x.r.d / TW::SIZE);
            let x_end = x.p.add((x.r.n + TW::SIZE - 1) / TW::SIZE);
            !(x_end <= begin || end <= x_begin)
        }
    }

    /// Is the slice empty?
    #[inline]
    pub fn is_empty(self) -> bool {
        self.r.is_empty()
    }

    /// The total size of the slice.
    #[inline]
    pub fn total_size(self) -> usize {
        self.r.total_size()
    }

    /// Size of the dropped slice, ie. the number of trits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.r.dropped_size()
    }

    /// Size of the current slice, ie. the number of trits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        self.r.avail_size()
    }

    /// Size of the current slice, ie. the number of trits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.r.size()
    }

    /// Size of the current slice but no more than `s`.
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        self.r.size_min(s)
    }

    fn with_range(self, r: SliceRange) -> Self {
        Self {
            r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Take `n` trits from the current slice.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        self.with_range(self.r.take(n))
    }

    /// Take no more than `n` trits from the current slice.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        self.with_range(self.r.take_min(n))
    }

    /// Drop `n` trits from the current slice.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        self.with_range(self.r.drop(n))
    }

    /// Drop no more than `n` trits from the current slice.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        self.with_range(self.r.drop_min(n))
    }

    /// Take and drop `n` trits from the current slice.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        let (t, d) = self.r.split_at(n);
        (self.with_range(t), self.with_range(d))
    }

    /// Take and drop no more than `n` trits from the current range.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let (t, d) = self.r.split_at_min(n);
        (self.with_range(t), self.with_range(d))
    }

    /// Pickup `n` trits from the dropped slice.
    #[inline]
    pub fn pickup(self, n: usize) -> Self {
        self.with_range(self.r.pickup(n))
    }

    /// Pickup all the dropped trits.
    #[inline]
    pub fn pickup_all(self) -> Self {
        self.with_range(self.r.pickup_all())
    }

    /// Drop all the current trits.
    #[inline]
    pub fn drop_all(self) -> Self {
        self.with_range(self.r.drop_all())
    }

    /// The dropped slice.
    #[inline]
    pub fn dropped(self) -> Self {
        self.with_range(self.r.dropped())
    }

    /// Advance the current slice by `n` trits.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let t = self.take(n);
        *self = self.drop(n);
        t
    }

    /// Difference between the current advanced slice and `s` slice.
    #[inline]
    pub fn diff(self, s: Self) -> Self {
        debug_assert_eq!(self.p, s.p);
        self.with_range(self.r.diff(s.r))
    }

    pub fn eq(self, other: Self) -> bool {
        self.as_const().eq(other.as_const())
    }
    pub fn eq_min(self, other: Self) -> (bool, usize) {
        self.as_const().eq_min(other.as_const())
    }
}

impl<'a, TW: 'a> TritSliceMutT<'a, TW>
where
    TW: TritWord + Copy,
{
    pub fn put_trit(self, t: Trit) {
        debug_assert!(!self.is_empty());
        TW::put_trit(self.r.d, self.p, t)
    }
    pub fn put_tryte(self, t: Tryte) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::put_tryte(self.r.d, self.p, t)
    }
    pub fn put1s(mut self, t1s: &[Trint1]) {
        debug_assert!(self.size() >= t1s.len());
        for t in t1s {
            self.put1(*t);
            self = self.drop(1);
        }
    }
    pub fn put1(self, t: Trint1) {
        debug_assert!(self.r.d < self.r.n);
        TW::put1(self.r.d, self.p, t)
    }
    pub fn put3(self, t: Trint3) {
        debug_assert!(self.r.d + 3 <= self.r.n);
        TW::put3(self.r.d, self.p, t)
    }
    pub fn put6(self, t: Trint6) {
        debug_assert!(self.r.d + 6 <= self.r.n);
        TW::put6(self.r.d, self.p, t)
    }
    pub fn put9(self, t: Trint9) {
        debug_assert!(self.r.d + 9 <= self.r.n);
        TW::put9(self.r.d, self.p, t)
    }
    pub fn put18(self, t: Trint18) {
        debug_assert!(self.r.d + 18 <= self.r.n);
        TW::put18(self.r.d, self.p, t)
    }
    /// Try to ASCII-convert a char `c` to a tryte and put it at the current offset.
    pub fn put_char(self, c: char) -> bool {
        if let Ok(t) = Trint3::try_from(c) {
            let ts = <[Trint1; 3]>::from(t);

            // Trits are padded with zeros when converted to char.
            for k in self.size_min(3)..3 {
                if Trint1(0) != ts[k] {
                    return false;
                }
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
            if !self.put_char(c) {
                return false;
            }
            self = self.drop_min(3);
        }
        true
    }

    /// Increment trits in the range `[d..n)` as integer.
    pub fn inc(mut self) -> bool {
        while !self.is_empty() {
            let t = Trit((1 + self.as_const().get_trit().0) % 3);
            self.put_trit(t);
            if 0 != t.0 {
                return true;
            }
            self = self.drop(1);
        }
        false
    }

    pub fn set_trit(mut self, t: Trit) {
        debug_assert!(t.0 < 3);
        while !self.is_empty() {
            self.put_trit(t);
            self = self.drop(1);
        }
    }
    pub fn swap_add(self, s: Self) {
        debug_assert_eq!(self.size(), s.size());
        TW::unsafe_swap_add(self.size(), self.r.d, self.p, s.r.d, s.p);
    }
    pub fn swap_add_min(self, s: Self) -> usize {
        let x = self.take_min(s.size());
        let n = x.size();
        x.swap_add(s.take(n));
        n
    }

    pub fn swap_sub(self, s: Self) {
        debug_assert_eq!(self.size(), s.size());
        TW::unsafe_swap_sub(self.size(), self.r.d, self.p, s.r.d, s.p);
    }
    pub fn swap_sub_min(self, s: Self) -> usize {
        let x = self.take_min(s.size());
        let n = x.size();
        x.swap_sub(s.take(n));
        n
    }
}

impl<'a, TW> PartialEq for TritSliceMutT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_const() == other.as_const()
    }
}
impl<'a, TW> Eq for TritSliceMutT<'a, TW> where TW: BasicTritWord + Copy {}

impl<'a, TW> fmt::Display for TritSliceMutT<'a, TW>
where
    TW: TritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_const())
    }
}

impl<'a, TW> fmt::Debug for TritSliceMutT<'a, TW>
where
    TW: BasicTritWord + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_const())
    }
}
