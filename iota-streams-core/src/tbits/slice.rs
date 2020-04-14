use std::{
    fmt,
    hash,
};

use super::word::*;

/// Range of the form `[d..n)` where `0 <= d <= n`.
///
/// Safe range operations return a subrange of `self`,
/// ie. `[d'..n')` such that `d <= d' <= n' <= n`.
///
/// Unsafe range operations go out of range to the left,
/// ie. `[d'..n')` such that `0 <= d' <= n' <= n`.
///
/// All safe and unsafe range operations check range bounds and panic in case of check failure.
#[derive(Copy, Clone, Debug)]
pub struct SliceRange {
    /// The right bound (ie. total range size).
    pub(crate) n: usize,
    /// The left bound (ie. current offset).
    pub(crate) d: usize,
}

impl SliceRange {
    /// Create a new range from total size and current offset.
    pub fn new(n: usize, d: usize) -> Self {
        assert!(d <= n);
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

    /// Size of the dropped range, ie. the number of tbits available before the current offset.
    #[inline]
    pub fn dropped_size(self) -> usize {
        self.d
    }

    /// Size of the current range, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn avail_size(self) -> usize {
        debug_assert!(self.n >= self.d);
        self.n - self.d
    }

    /// Size of the current range, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn size(self) -> usize {
        self.avail_size()
    }

    /// Size of the current range but no more than `s`.
    #[inline]
    pub fn size_min(self, s: usize) -> usize {
        std::cmp::min(self.size(), s)
    }

    /// Return current offset shifted by `n` to the right but no further than right bound.
    #[inline]
    pub fn offset_min(self, n: usize) -> usize {
        std::cmp::min(self.n, self.d + n)
    }

    /// Take `n` tbits from the current range.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        assert!(self.n >= self.d + n);
        Self {
            n: self.d + n,
            d: self.d,
        }
    }

    /// Take no more than `n` tbits from the current range.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        Self {
            n: self.offset_min(n),
            d: self.d,
        }
    }

    /// Split range at `n` tbits, return head and assign tail to self.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let middle = self.d + n;
        assert!(self.n >= middle);
        let left = self.d;
        self.d = middle;
        Self { n: middle, d: left }
    }

    /// Split range at `n` tbits, return head and assign tail to self.
    #[inline]
    pub fn advance_min(&mut self, n: usize) -> Self {
        let middle = self.offset_min(n);
        let left = self.d;
        self.d = middle;
        Self { n: middle, d: left }
    }

    /// Drop `n` tbits from the current range.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        assert!(self.n >= self.d + n);
        Self {
            n: self.n,
            d: self.d + n,
        }
    }

    /// Drop no more than `n` tbits from the current range.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        Self {
            n: self.n,
            d: self.offset_min(n),
        }
    }

    /// Take and drop `n` tbits from the current range.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        let middle = self.d + n;
        assert!(self.n >= middle);
        (Self { n: middle, d: self.d }, Self { n: self.n, d: middle })
    }

    /// Take and drop no more than `n` tbits from the current range
    /// and return `(head,tail)`.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let middle = self.offset_min(n);
        (Self { n: middle, d: self.d }, Self { n: self.n, d: middle })
    }

    /// Pickup `n` tbits from the dropped range.
    #[inline]
    pub unsafe fn pickup(self, n: usize) -> Self {
        assert!(self.d >= n);
        Self {
            n: self.n,
            d: self.d - n,
        }
    }

    /// Pickup all the dropped tbits.
    #[inline]
    pub unsafe fn pickup_all(self) -> Self {
        Self { n: self.n, d: 0 }
    }

    /// Drop all the current tbits.
    #[inline]
    pub fn drop_all(self) -> Self {
        Self { n: self.n, d: self.n }
    }

    /// The dropped range.
    #[inline]
    pub unsafe fn dropped(self) -> Self {
        Self { n: self.d, d: 0 }
    }

    /// Difference between the current advanced range and `s` range.
    #[inline]
    pub unsafe fn diff(self, s: Self) -> Self {
        assert!(s.d <= self.d && self.d <= s.n);
        Self { n: self.d, d: s.d }
    }
}

/// A constant tbit slice represented as a (mutable) pointer to tbit words
/// (each word contains one or more tbits) and a range in tbits within the array.
///
/// Constant slice is a light-weight safe-copyable object.
#[derive(Copy, Clone)]
pub struct TbitSlice<'a, TW: 'a> {
    /// Current slice range.
    pub(crate) r: SliceRange,
    /// Base pointer, always stays constant.
    pub(crate) p: *const TW,
    /// Slice life-time marker.
    pub(crate) phantom: std::marker::PhantomData<&'a TW>,
}

impl<'a, TW: 'a> TbitSlice<'a, TW> {
    /// Is the slice empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.r.is_empty()
    }

    /// The total size of the slice.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.r.total_size()
    }

    /// Size of the dropped slice, ie. the number of tbits available before the current offset.
    #[inline]
    pub fn dropped_size(&self) -> usize {
        self.r.dropped_size()
    }

    /// Size of the current slice, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn avail_size(&self) -> usize {
        self.r.avail_size()
    }

    /// Size of the current slice, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn size(&self) -> usize {
        self.r.size()
    }

    /// Size of the current slice but no more than `s`.
    #[inline]
    pub fn size_min(&self, s: usize) -> usize {
        self.r.size_min(s)
    }

    /// Range modifying transform. The function is safe if the new range `r` is safe.
    fn with_range(self, r: SliceRange) -> Self {
        Self {
            r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Range modifying transform. The function is safe if the ranges `r1` and `r2` are safe.
    fn with_range2(self, r1: SliceRange, r2: SliceRange) -> (Self, Self) {
        (
            Self {
                r: r1,
                p: self.p,
                phantom: std::marker::PhantomData,
            },
            Self {
                r: r2,
                p: self.p,
                phantom: std::marker::PhantomData,
            },
        )
    }

    /// Range modifying transform. Return slice with the new range `r_new` and
    /// update self range to `r_mut`. The function is safe if the ranges
    /// `r_mut` and `r_new` are safe (they can be overlapping).
    fn with_range_mut(&mut self, r_mut: SliceRange, r_new: SliceRange) -> Self {
        self.r = r_mut;
        Self {
            r: r_new,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW: 'a> TbitSlice<'a, TW>
where
    TW: BasicTbitWord,
{
    /// Create slice of size `n` pointing to `p`.
    pub fn from_raw_ptr(n: usize, p: *const TW) -> Self {
        Self {
            r: SliceRange::new(n, 0),
            p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Split slice into chunks.
    pub fn chunks(mut self, chunk_size: usize) -> Vec<Self> {
        // Can't divide by zero.
        assert!(chunk_size != 0);
        let chunks_count = (self.size() + chunk_size - 1) / chunk_size;
        let mut v = Vec::with_capacity(chunks_count);
        while !self.is_empty() {
            v.push((&mut self).advance_min(chunk_size));
        }
        v
    }

    /// Create slice of `n` tbits pointing to the array slice `t`.
    pub fn from_slice(n: usize, t: &'a [TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self::from_raw_ptr(n, t.as_ptr())
    }

    /// Copy tbits from `self` slice into `tbits`.
    pub fn get_tbits(&self, tbits: &mut [TW::Tbit]) {
        unsafe {
            assert!(self.size() >= tbits.len());
            TW::to_tbits(self.size(), self.r.d, self.p, tbits.as_mut_ptr());
        }
    }

    /// Check whether `self` and `x` slices are overlapping.
    ///
    /// If you need `is_overlapping` then your code is probably unsafe.
    /// It should only be used in debug code.
    #[cfg(debug_assertions)]
    pub(crate) unsafe fn is_overlapping(&self, x: &Self) -> bool {
        let begin = self.p.add(self.r.d / TW::SIZE);
        let end = self.p.add((self.r.n + TW::SIZE - 1) / TW::SIZE);
        let x_begin = x.p.add(x.r.d / TW::SIZE);
        let x_end = x.p.add((x.r.n + TW::SIZE - 1) / TW::SIZE);
        !(x_end <= begin || end <= x_begin)
    }

    /// Take `n` tbits from the current slice.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        self.with_range(self.r.take(n))
    }

    /// Take no more than `n` tbits from the current slice.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        self.with_range(self.r.take_min(n))
    }

    /// Drop `n` tbits from the current slice.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        self.with_range(self.r.drop(n))
    }

    /// Drop no more than `n` tbits from the current slice.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        self.with_range(self.r.drop_min(n))
    }

    /// Take and drop `n` tbits from the current slice.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        let (head, tail) = self.r.split_at(n);
        self.with_range2(head, tail)
    }

    /// Take and drop no more than `n` tbits from the current range.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let (head, tail) = self.r.split_at_min(n);
        self.with_range2(head, tail)
    }

    /// Advance the current slice by `n` tbits.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let (head, tail) = self.r.split_at(n);
        self.with_range_mut(tail, head)
    }

    /// Advance the current slice by no more than `n` tbits.
    #[inline]
    pub fn advance_min(&mut self, n: usize) -> Self {
        let (r_head, r_tail) = self.r.split_at_min(n);
        self.with_range_mut(r_tail, r_head)
    }

    /// Pickup `n` tbits from the dropped slice.
    #[inline]
    pub unsafe fn pickup(self, n: usize) -> Self {
        let r = self.r.pickup(n);
        self.with_range(r)
    }

    /// Mutable variant of `pickup`.
    #[inline]
    pub unsafe fn pickup_mut(&mut self, n: usize) {
        self.r = self.r.pickup(n);
    }

    /// Pickup all the dropped tbits.
    #[inline]
    pub unsafe fn pickup_all(self) -> Self {
        let r = self.r.pickup_all();
        self.with_range(r)
    }

    /// Mutable variant of `pickup_all`.
    #[inline]
    pub unsafe fn pickup_all_mut(&mut self) {
        self.r = self.r.pickup_all();
    }

    /// Drop all the current tbits.
    #[inline]
    pub fn drop_all(self) -> Self {
        let r = self.r.drop_all();
        self.with_range(r)
    }

    /// The dropped slice.
    #[inline]
    pub unsafe fn dropped(self) -> Self {
        let r = self.r.dropped();
        self.with_range(r)
    }

    /// Difference between the current advanced slice and `s` slice.
    #[inline]
    pub unsafe fn diff(self, s: Self) -> Self {
        assert_eq!(self.p, s.p);
        let r = self.r.diff(s.r);
        self.with_range(r)
    }

    /// Compare two slices of the same size.
    pub fn equals(&self, other: &Self) -> bool {
        assert_eq!(self.size(), other.size());
        unsafe { TW::equals(self.size(), self.r.d, self.p, other.r.d, other.p) }
    }

    /// Compare two slices.
    pub fn equals_min(&self, other: &Self) -> (bool, usize) {
        let n = self.size_min(other.size());
        unsafe { (TW::equals(n, self.r.d, self.p, other.r.d, other.p), n) }
    }

    /// Copy tbits into the slice `to` of equal size.
    pub fn copy(&self, to: &TbitSliceMut<'a, TW>) {
        assert_eq!(self.size(), to.size());
        debug_assert!(unsafe { !self.is_overlapping(&to.as_const()) });
        unsafe { TW::copy(self.size(), self.r.d, self.p, to.r.d, to.p) }
    }

    /// Copy tbits into the slice `to` of equal size.
    pub fn copy_min(&self, to: &TbitSliceMut<'a, TW>) -> usize {
        debug_assert!(unsafe { !self.is_overlapping(&to.as_const()) });
        let n = self.size_min(to.size());
        unsafe { TW::copy(n, self.r.d, self.p, to.r.d, to.p) }
        n
    }
}

impl<'a, TW: 'a> TbitSlice<'a, TW>
where
    TW: StringTbitWord,
{
    /// Get a tryte at the current offset and ASCII-convert it as char.
    pub fn get_char(&self) -> char {
        unsafe { TW::get_char(self.size_min(TW::TBITS_PER_CHAR), self.r.d, self.p) }
    }

    /// ASCII encode trytes at the current offset.
    /// The last incomplete tryte if any is padded with zero trits.
    pub fn to_str(&self) -> String {
        let mut s = String::with_capacity((self.size() + TW::TBITS_PER_CHAR - 1) / TW::TBITS_PER_CHAR);
        unsafe {
            let mut d = self.r.d;
            while d < self.r.n {
                s.push(TW::get_char(self.r.n - d, d, self.p));
                d += TW::TBITS_PER_CHAR;
            }
            s
        }
    }

    pub fn eq_str(&self, s: &str) -> bool {
        if (self.size() + TW::TBITS_PER_CHAR - 1) / TW::TBITS_PER_CHAR != s.len() {
            return false;
        }

        unsafe {
            let mut d = self.r.d;
            for c in s.chars() {
                let c2 = TW::get_char(self.r.n - d, d, self.p);
                if c != c2 {
                    return false;
                }
                d += TW::TBITS_PER_CHAR;
            }
            true
        }
    }
}

impl<'a, TW: 'a> TbitSlice<'a, TW>
where
    TW: IntTbitWord,
{
    pub fn get_isize(&self) -> isize {
        unsafe { TW::get_isize(self.size(), self.r.d, self.p) }
    }
    pub fn get_usize(&self) -> usize {
        unsafe { TW::get_usize(self.size(), self.r.d, self.p) }
    }
}

impl<'a, TW> PartialEq for TbitSlice<'a, TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && self.equals(other)
    }
}
impl<'a, TW> Eq for TbitSlice<'a, TW> where TW: BasicTbitWord {}

impl<'a, TW> hash::Hash for TbitSlice<'a, TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        unsafe {
            <TW as BasicTbitWord>::fold_tbits(self.size(), self.r.d, self.p, |t| t.hash(state));
        }
    }
}

impl<'a, TW> fmt::Display for TbitSlice<'a, TW>
where
    TW: StringTbitWord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;
        let mut this = *self;
        while !this.is_empty() {
            f.write_char(this.get_char())?;
            this = this.drop_min(TW::TBITS_PER_CHAR);
        }
        Ok(())
    }
}

unsafe fn write_tbits<TW>(n: usize, dx: usize, x: *const TW, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    if n == 0 {
        return Ok(());
    }

    let mut v = vec![TW::ZERO_TBIT; TW::SIZE];
    let rx = dx % TW::SIZE;
    let mut xx = x.add(dx / TW::SIZE);
    let mut nn = n;
    let mut d;

    if rx != 0 {
        d = std::cmp::min(n, TW::SIZE - rx);
        TW::word_to_tbits(*xx, v.as_mut_ptr());
        for t in v[rx..rx + d].into_iter() {
            write!(f, "{}", t)?;
        }
        nn -= d;
        xx = xx.add(1);
    }

    d = TW::SIZE;
    while nn >= d {
        TW::word_to_tbits(*xx, v.as_mut_ptr());
        for t in v[..].into_iter() {
            write!(f, "{}", t)?;
        }
        nn -= d;
        xx = xx.add(1);
    }

    if nn > 0 {
        TW::word_to_tbits(*xx, v.as_mut_ptr());
        for t in v[..nn].into_iter() {
            write!(f, "{}", t)?;
        }
    }

    Ok(())
}

impl<'a, TW> fmt::Debug for TbitSlice<'a, TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            write!(f, "({},{},{:?}):", self.r.n, self.r.d, self.p)?;
            write!(f, "[")?;
            write_tbits::<TW>(self.r.d, 0, self.p, f)?;
            write!(f, "|")?;
            write_tbits::<TW>(self.r.n - self.r.d, self.r.d, self.p, f)?;
            write!(f, "]")?;
            write!(f, "")
        }
    }
}

/// A mutable tbit slice represented as a (constant) pointer to tbit words
/// (each word contains one or more tbits) and a range in tbits within the array.
///
/// Mutable slice is a light-weight non-copyable object.
/// Although it's usually safe to have multiple copies of a mutable slice
/// (or to have multiple slices with overlapping ranges) the mutable slice type is
/// made non-copyable to increase (but not totally guarantee) reference safety.
///
/// Methods taking `self` consume object and modify tbits.
/// Methods taking `&mut self` modify tbits and modify slice range which is not very convenient.
/// The solution is either to `pickup` dropped tbits or to use consuming counterpart and
/// pass an unsafe `clone`d object.
///
/// NB. One case of accepted unsafe code is where two mutable slices with non-overlapping
/// ranges `[a..b)` and `[b..c)` are modified concurrently (in parallel threads or
/// in the same function as the compiler expects mutable pointers to be non-aliasing).
/// If the offset `b` points in the middle of the tbit word the pointer
/// `p.add(b / TW::SIZE)` will be aliased. It's only possible with tbit word
/// implementations with `SIZE > 1`.
///
/// The general rule is to avoid mutable operations with neighbouring slices in the same function.
/// TODO: Ensure that this rule is satisfied throughout the crates (including Spongos,
/// MSS, NTRU, Protobuf3).
pub struct TbitSliceMut<'a, TW: 'a> {
    /// Current slice range.
    pub(crate) r: SliceRange,
    /// Base pointer, always stays constant.
    pub(crate) p: *mut TW,
    /// Slice life-time marker.
    pub(crate) phantom: std::marker::PhantomData<&'a TW>,
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW> {
    /// Is the slice empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.r.is_empty()
    }

    /// The total size of the slice.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.r.total_size()
    }

    /// Size of the dropped slice, ie. the number of tbits available before the current offset.
    #[inline]
    pub fn dropped_size(&self) -> usize {
        self.r.dropped_size()
    }

    /// Size of the current slice, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn avail_size(&self) -> usize {
        self.r.avail_size()
    }

    /// Size of the current slice, ie. the number of tbits available after the current offset.
    #[inline]
    pub fn size(&self) -> usize {
        self.r.size()
    }

    /// Size of the current slice but no more than `s`.
    #[inline]
    pub fn size_min(&self, s: usize) -> usize {
        self.r.size_min(s)
    }

    /// Range modifying transform. The function is safe if the new range `r` is safe.
    #[inline]
    fn with_range(self, r: SliceRange) -> Self {
        Self {
            r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Range modifying transform. The function is safe if the ranges `r1` and `r2` are safe and non-overlapping.
    #[inline]
    fn with_range2(self, r1: SliceRange, r2: SliceRange) -> (Self, Self) {
        (
            Self {
                r: r1,
                p: self.p,
                phantom: std::marker::PhantomData,
            },
            Self {
                r: r2,
                p: self.p,
                phantom: std::marker::PhantomData,
            },
        )
    }

    /// Range modifying transform. Return slice with the new range `r_new` and
    /// update self range to `r_mut`. The function is safe if the ranges
    /// `r_mut` and `r_new` are safe and non-overlapping.
    #[inline]
    fn with_range_mut(&mut self, r_mut: SliceRange, r_new: SliceRange) -> Self {
        self.r = r_mut;
        Self {
            r: r_new,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW>
where
    TW: BasicTbitWord,
{
    /// Create slice of `n` tbits pointing to the array slice `t`.
    pub fn from_raw_ptr(n: usize, p: *mut TW) -> Self {
        Self {
            r: SliceRange::new(n, 0),
            p,
            phantom: std::marker::PhantomData,
        }
    }

    /// Create slice of `n` tbits pointing to the array slice `t`.
    pub fn from_slice_mut(n: usize, t: &'a mut [TW]) -> Self {
        debug_assert!(n <= t.len() * TW::SIZE);
        Self::from_raw_ptr(n, t.as_mut_ptr())
    }

    /// Cycle non-empty slice `ts` to fill `self`.
    pub fn cycle(&mut self, ts: TbitSlice<'a, TW>) {
        //TODO: &mut self -> mut self
        assert!(!ts.is_empty());
        while !self.is_empty() {
            ts.copy_min(&self.advance_min(ts.size()));
        }
    }

    /// Convert into const slice.
    pub fn into_const(self) -> TbitSlice<'a, TW> {
        TbitSlice::<'a, TW> {
            r: self.r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /*
    /// A safer variant of `as_const`, `f` must not capture `self`.
    pub fn with_const<F>(&mut self, f: F) where F: FnOnce(TbitSlice<'a, TW>) {
        f(TbitSlice::<'a, TW> {
            r: self.r,
            p: self.p,
            phantom: std::marker::PhantomData,
        })
    }
     */

    /// Convert to a constant slice, creating a new reference to the same mutable object.
    /// This not const slice object must be short-lived.
    pub unsafe fn as_const(&self) -> TbitSlice<'a, TW> {
        //TODO: &mut self?
        TbitSlice::<'a, TW> {
            r: self.r,
            p: self.p,
            phantom: std::marker::PhantomData,
        }
    }

    /// This function is here deliberately as mutable slice is not `Clone`.
    #[inline]
    pub unsafe fn clone(&self) -> Self {
        Self {
            r: self.r,
            p: self.p,
            phantom: self.phantom,
        }
    }

    /// Copy tbits into `self` slice from `tbits`.
    pub fn put_tbits(&self, tbits: &[<TW as BasicTbitWord>::Tbit]) {
        unsafe {
            assert!(self.size() >= tbits.len());
            TW::from_tbits(self.size(), self.r.d, self.p, tbits.as_ptr());
        }
    }

    /// Fill slice with zero tbits.
    pub fn set_zero(&self) {
        unsafe {
            TW::set_zero(self.size(), self.r.d, self.p);
        }
    }

    /// Take `n` tbits from the current slice.
    #[inline]
    pub fn take(self, n: usize) -> Self {
        let r = self.r.take(n);
        self.with_range(r)
    }

    /// Take no more than `n` tbits from the current slice.
    #[inline]
    pub fn take_min(self, n: usize) -> Self {
        let r = self.r.take_min(n);
        self.with_range(r)
    }

    /// Drop `n` tbits from the current slice.
    #[inline]
    pub fn drop(self, n: usize) -> Self {
        let r = self.r.drop(n);
        self.with_range(r)
    }

    /// Drop no more than `n` tbits from the current slice.
    #[inline]
    pub fn drop_min(self, n: usize) -> Self {
        let r = self.r.drop_min(n);
        self.with_range(r)
    }

    /// Take and drop `n` tbits from the current slice.
    #[inline]
    pub fn split_at(self, n: usize) -> (Self, Self) {
        let (head, tail) = self.r.split_at(n);
        self.with_range2(head, tail)
    }

    /// Take and drop no more than `n` tbits from the current range.
    #[inline]
    pub fn split_at_min(self, n: usize) -> (Self, Self) {
        let (head, tail) = self.r.split_at_min(n);
        self.with_range2(head, tail)
    }

    /// Advance the current slice by `n` tbits.
    #[inline]
    pub fn advance(&mut self, n: usize) -> Self {
        let (head, tail) = self.r.split_at(n);
        self.with_range_mut(tail, head)
    }

    /// Advance the current slice by no more than `n` tbits.
    #[inline]
    pub fn advance_min(&mut self, n: usize) -> Self {
        let (r_head, r_tail) = self.r.split_at_min(n);
        self.with_range_mut(r_tail, r_head)
    }

    /// Pickup `n` tbits from the dropped slice.
    /// This unsafely gives mutable access to a region possibly owned by another mutable slice.
    #[inline]
    pub unsafe fn pickup(self, n: usize) -> Self {
        let r = self.r.pickup(n);
        self.with_range(r)
    }

    /// Mutable variant of `pickup`.
    #[inline]
    pub unsafe fn pickup_mut(&mut self, n: usize) {
        self.r = self.r.pickup(n);
    }

    /// Pickup all the dropped tbits.
    /// This unsafely gives mutable access to a region possibly owned by another mutable slice.
    #[inline]
    pub unsafe fn pickup_all(self) -> Self {
        let r = self.r.pickup_all();
        self.with_range(r)
    }

    /// Mutable variant of `pickup_all`.
    #[inline]
    pub unsafe fn pickup_all_mut(&mut self) {
        self.r = self.r.pickup_all();
    }

    /// Drop all the current tbits.
    #[inline]
    pub fn drop_all(self) -> Self {
        let r = self.r.drop_all();
        self.with_range(r)
    }

    /// The dropped slice.
    #[inline]
    pub unsafe fn dropped(self) -> Self {
        let r = self.r.dropped();
        self.with_range(r)
    }

    /// Difference between the current advanced slice and `s` slice.
    #[inline]
    pub unsafe fn diff(self, s: Self) -> Self {
        assert_eq!(self.p, s.p);
        let r = self.r.diff(s.r);
        self.with_range(r)
    }

    /// Compare two slices of the same size.
    pub fn equals(&self, other: &Self) -> bool {
        assert_eq!(self.size(), other.size());
        unsafe {
            TW::equals(
                self.size(),
                self.r.d,
                self.p as *const TW,
                other.r.d,
                other.p as *const TW,
            )
        }
    }

    /// Compare two slices.
    pub fn equals_min(&self, other: &Self) -> (bool, usize) {
        let n = self.size_min(other.size());
        unsafe {
            (
                TW::equals(n, self.r.d, self.p as *const TW, other.r.d, other.p as *const TW),
                n,
            )
        }
    }
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW>
where
    TW: StringTbitWord,
{
    /// Try to ASCII-convert a char `c` to a tryte and put it at the current offset.
    pub fn put_char(&mut self, c: char) -> bool {
        unsafe { TW::put_char(self.size_min(TW::TBITS_PER_CHAR), self.r.d, self.p, c) }
    }

    /// Try to ASCII-convert string `s` to trytes and put them at the current offset.
    /// If the length of `s` exceeds the size of the slice the remaining trits of `s` must be zero.
    pub fn from_str(&mut self, s: &str) -> bool {
        unsafe {
            let mut d = self.r.d;
            for c in s.chars() {
                if d >= self.r.n {
                    break;
                }
                if !TW::put_char(self.r.n - d, d, self.p, c) {
                    return false;
                }
                d += TW::TBITS_PER_CHAR;
            }
            true
        }
    }
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW>
where
    TW: IntTbitWord,
{
    pub fn put_isize(&self, i: isize) {
        unsafe { TW::put_isize(self.size(), self.r.d, self.p, i) }
    }
    pub fn put_usize(&self, u: usize) {
        unsafe { TW::put_usize(self.size(), self.r.d, self.p, u) }
    }
}

impl<'a, TW: 'a> TbitSliceMut<'a, TW>
where
    TW: SpongosTbitWord,
{
    pub fn absorb_overwrite(&mut self, x: TbitSlice<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        unsafe {
            TW::absorb_overwrite(self.r.d, self.p, n, x.r.d, x.p);
        }
    }
    pub fn absorb_xor(&mut self, x: TbitSlice<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        unsafe {
            TW::absorb_xor(self.r.d, self.p, n, x.r.d, x.p);
        }
    }

    pub fn squeeze_overwrite(&mut self, y: &TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe {
            TW::squeeze_overwrite(self.r.d, self.p, n, y.r.d, y.p);
        }
    }
    pub fn squeeze_xor(&mut self, y: &TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe {
            TW::squeeze_xor(self.r.d, self.p, n, y.r.d, y.p);
        }
    }

    pub fn squeeze_eq_overwrite(&mut self, y: TbitSlice<'a, TW>) -> bool {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe { TW::squeeze_eq_overwrite(self.r.d, self.p, n, y.r.d, y.p) }
    }
    pub fn squeeze_eq_xor(&mut self, y: TbitSlice<'a, TW>) -> bool {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe { TW::squeeze_eq_xor(self.r.d, self.p, n, y.r.d, y.p) }
    }

    pub fn encrypt_overwrite(&mut self, x: TbitSlice<'a, TW>, y: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        assert_eq!(n, y.size());
        unsafe {
            TW::encrypt_overwrite(self.r.d, self.p, n, x.r.d, x.p, y.r.d, y.p);
        }
    }
    pub fn encrypt_xor(&mut self, x: TbitSlice<'a, TW>, y: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        assert_eq!(n, y.size());
        unsafe {
            TW::encrypt_xor(self.r.d, self.p, n, x.r.d, x.p, y.r.d, y.p);
        }
    }
    pub fn encrypt_overwrite_mut(&mut self, x: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        unsafe {
            TW::encrypt_overwrite_mut(self.r.d, self.p, n, x.r.d, x.p);
        }
    }
    pub fn encrypt_xor_mut(&mut self, x: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, x.size());
        unsafe {
            TW::encrypt_xor_mut(self.r.d, self.p, n, x.r.d, x.p);
        }
    }

    pub fn decrypt_overwrite(&mut self, y: TbitSlice<'a, TW>, x: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        assert_eq!(n, x.size());
        unsafe {
            TW::decrypt_overwrite(self.r.d, self.p, n, y.r.d, y.p, x.r.d, x.p);
        }
    }
    pub fn decrypt_xor(&mut self, y: TbitSlice<'a, TW>, x: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        assert_eq!(n, x.size());
        unsafe {
            TW::decrypt_xor(self.r.d, self.p, n, y.r.d, y.p, x.r.d, x.p);
        }
    }
    pub fn decrypt_overwrite_mut(&mut self, y: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe {
            TW::decrypt_overwrite_mut(self.r.d, self.p, n, y.r.d, y.p);
        }
    }
    pub fn decrypt_xor_mut(&mut self, y: &mut TbitSliceMut<'a, TW>) {
        let n = self.size();
        assert_eq!(n, y.size());
        unsafe {
            TW::decrypt_xor_mut(self.r.d, self.p, n, y.r.d, y.p);
        }
    }
}

impl<'a, TW: 'a> PartialEq for TbitSliceMut<'a, TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.size() == other.size() && self.equals(other)
    }
}
impl<'a, TW> Eq for TbitSliceMut<'a, TW> where TW: BasicTbitWord + Copy {}

impl<'a, TW> fmt::Display for TbitSliceMut<'a, TW>
where
    TW: StringTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{}", self.as_const()) }
    }
}

impl<'a, TW> fmt::Debug for TbitSliceMut<'a, TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.as_const()) }
    }
}
