//use std::convert::{AsMut, AsRef, From, TryFrom};
use std::fmt;
//use std::hash;

use crate::tbits::{word::{BasicTbitWord, SpongosTbitWord}, TbitSliceT, TbitSliceMutT, Tbits};
use super::prp::PRP;

/// Rate -- size of outer part of the Spongos state.
pub const RATE: usize = 486;

/// Capacity -- size of inner part of the Spongos state.
pub const CAPACITY: usize = 243;

/// Width -- size of the Spongos state.
pub const WIDTH: usize = RATE + CAPACITY;

/// Sponge fixed key size.
pub const KEY_SIZE: usize = 243;

/// Sponge fixed hash size.
pub const HASH_SIZE: usize = 243;

/// Sponge fixed MAC size.
pub const MAC_SIZE: usize = 243;

/// Implemented as a separate from `Spongos` struct in order to deal with life-times.
#[derive(Clone)]
struct OuterT<TW> {
    /// Current position in the outer state.
    pos: usize,
    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    tbits: Tbits<TW>,
}

impl<TW> OuterT<TW>
where
    TW: BasicTbitWord,
{
    /// `outer` must not be assigned to a variable.
    /// It must be used via `self.outer.slice()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer` object.
    fn slice(&self) -> TbitSliceT<TW> {
        //debug_assert!(self.trits.size() >= RATE);
        //debug_assert!(self.pos <= RATE);
        self.tbits.slice().drop(self.pos)
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer.slice_mut()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    fn slice_mut(&mut self) -> TbitSliceMutT<TW> {
        //debug_assert!(self.trits.size() >= RATE);
        //debug_assert!(self.pos <= RATE);
        self.tbits.slice_mut().drop(self.pos)
    }

    /// Available size of the outer tbits.
    fn size(&self) -> usize {
        self.tbits.size() - self.pos
    }
}

impl<TW> fmt::Debug for OuterT<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.pos, self.tbits)
    }
}

#[derive(Clone)]
pub struct Spongos<TW, F> {
    /// Spongos transform.
    s: F,
    /// Outer state.
    outer: OuterT<TW>,
}

impl<TW, F> Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self {
            s: F::default(),
            outer: OuterT {
                pos: 0,
                tbits: Tbits::zero(F::RATE),
            },
        }
    }
}

impl<TW, F> Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
{
    /// Create a Spongos object with an explicit state.
    pub fn init_with_state(s: F) -> Self {
        Self {
            s,
            outer: OuterT {
                pos: 0,
                tbits: Tbits::zero(F::RATE),
            },
        }
    }

    /*
    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub fn to_inner(&self, mut inner: TritSliceMutT<TW>) {
        assert!(self.is_committed());
        assert_eq!(CAPACITY, inner.size());

        let n = inner.size();
        for idx in RATE..RATE + n {
            inner.put_trit(Trit(self.s.get1(idx)));
            inner = inner.drop(1);
        }
    }

    pub fn to_inner_trits(&self) -> Trits {
        let mut inner = Trits::zero(CAPACITY);
        self.to_inner(inner.slice_mut());
        inner
    }

    pub fn from_inner(mut inner: TritSlice) -> Self {
        assert_eq!(CAPACITY, inner.size());

        let mut s = Self::init();
        let n = inner.size();
        for idx in RATE..RATE + n {
            s.s.set1(idx, inner.get_trit().0);
            inner = inner.drop(1);
        }
        s
    }

    pub fn from_inner_trits(inner: &Trits) -> Self {
        Self::from_inner(inner.slice())
    }
     */

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(F::RATE < self.outer.pos + n));
        self.outer.pos += n;
        if F::RATE == self.outer.pos {
            self.commit();
        }
    }

    /// Absorb a trit slice into Spongos object.
    pub fn absorb(&mut self, mut x: TbitSliceT<TW>) {
        while !x.is_empty() {
            let n = std::cmp::min(x.size(), self.outer.size());
            x.take(n).copy(&mut self.outer.slice_mut());
            self.update(n);
            x = x.drop(n);
        }
    }

    /// Absorb Tbits.
    pub fn absorb_tbits(&mut self, x: &Tbits<TW>) {
        self.absorb(x.slice())
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, y: &mut TbitSliceMutT<TW>) {
        while !y.is_empty() {
            let mut head = y.advance_min(self.outer.size());
            let n = head.size();
            self.outer.slice().copy(&mut head);
            self.outer.slice_mut().take(n).set_zero();
            self.update(n);
        }
    }

    /// Squeeze a trit slice from Spongos object and compare.
    pub fn squeeze_eq(&mut self, mut y: TbitSliceT<TW>) -> bool {
        let mut eq = true;
        while !y.is_empty() {
            let n = std::cmp::min(y.size(), self.outer.size());
            let (head, tail) = y.split_at(n);
            // force constant-time equality
            let eqn = self.outer.slice().equals(&head);
            eq = eqn && eq;
            self.outer.slice_mut().take(n).set_zero();
            self.update(n);
            y = tail;
        }
        eq
    }

    /// Squeeze Tbits.
    pub fn squeeze_tbits(&mut self, n: usize) -> Tbits<TW> {
        let mut y = Tbits::zero(n);
        self.squeeze(&mut y.slice_mut());
        y
    }

    /// Squeeze Tbits and compare.
    pub fn squeeze_eq_tbits(&mut self, y: &Tbits<TW>) -> bool {
        self.squeeze_eq(y.slice())
    }

    /// Encrypt a trit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn encr(&mut self, mut x: TbitSliceT<TW>, y: &mut TbitSliceMutT<TW>) {
        //TODO: Fix is_overlapped.
        //debug_assert!(!x.is_overlapped(y.as_const()));
        assert_eq!(x.size(), y.size());
        while !x.is_empty() {
            let x_head = x.advance_min(self.outer.size());
            let n = x_head.size();
            let mut y_head = y.advance(n);
            x_head.copy_add(&mut self.outer.slice_mut().take(n), &mut y_head);
            self.update(n);
        }
    }

    /// Encrypt in-place a trit slice with Spongos object.
    pub fn encr_mut(&mut self, xy: &mut TbitSliceMutT<TW>) {
        while !xy.is_empty() {
            let mut head = xy.advance_min(self.outer.size());
            let n = head.size();
            head.swap_add(&mut self.outer.slice_mut().take(n));
            self.update(n);
        }
    }

    /// Encrypt Tbits.
    pub fn encr_tbits(&mut self, x: &Tbits<TW>) -> Tbits<TW> {
        let mut y = Tbits::zero(x.size());
        self.encr(x.slice(), &mut y.slice_mut());
        y
    }

    /// Encrypt Tbits in-place.
    pub fn encr_mut_tbits(&mut self, t: &mut Tbits<TW>) {
        let mut xy = t.slice_mut();
        self.encr_mut(&mut xy);
    }

    /// Decrypt a tbit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn decr(&mut self, mut x: TbitSliceT<TW>, mut y: TbitSliceMutT<TW>) {
        //TODO: Make Spongos `decr` type same as `encr`.
        //TODO: debug_assert!(!x.is_overlapped(y));
        assert_eq!(x.size(), y.size());
        while !x.is_empty() {
            let n = std::cmp::min(self.outer.size(), x.size());
            let (x_head, x_tail) = x.split_at(n);
            let (mut y_head, y_tail) = y.split_at(n);
            x_head.copy_sub_min(&mut self.outer.slice_mut().take(n), &mut y_head);
            self.update(n);
            x = x_tail;
            y = y_tail;
        }
    }

    /// Decrypt in-place a trit slice with Spongos object.
    pub fn decr_mut(&mut self, mut xy: TbitSliceMutT<TW>) {
        while !xy.is_empty() {
            let n = std::cmp::min(self.outer.size(), xy.size());
            let (mut head, tail) = xy.split_at(n);
            head.swap_sub_min(&mut self.outer.slice_mut().take(n));
            self.update(n);
            xy = tail;
        }
    }

    /// Decrypt Tbits.
    pub fn decr_tbits(&mut self, x: &Tbits<TW>) -> Tbits<TW> {
        let mut y = Tbits::zero(x.size());
        self.decr(x.slice(), y.slice_mut());
        y
    }

    /// Decrypt Tbits in-place.
    pub fn decr_mut_tbits(&mut self, t: &mut Tbits<TW>) {
        let xy = t.slice_mut();
        self.decr_mut(xy);
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub fn commit(&mut self) {
        if self.outer.pos != 0 {
            let mut o = self.outer.slice_mut();
            self.s.transform(&mut o);
            self.outer.pos = 0;
        }
    }

    /// Check whether spongos state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.outer.pos
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        let mut x = Tbits::zero(CAPACITY);
        joinee.squeeze(&mut x.slice_mut());
        self.absorb(x.slice());
    }
}

impl<TW, F> Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone,
{
    /// Fork Spongos object into another.
    /// Essentially this just creates a clone of self.
    pub fn fork_at(&self, fork: &mut Self) {
        fork.clone_from(self);
    }

    /// Fork Spongos object into a new one.
    /// Essentially this just creates a clone of self.
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

impl<TW, F> fmt::Debug for Spongos<TW, F>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.outer)
    }
}

/// Shortcut for `Spongos::init`.
pub fn init<TW, F>() -> Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    Spongos::init()
}

/*
/// Size of inner state.
pub const INNER_SIZE: usize = CAPACITY;

/// Convenience wrapper for storing Spongos inner state.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Inner(Tbits);

impl Default for Inner {
    fn default() -> Self {
        Self(Tbits::zero(INNER_SIZE))
    }
}

impl hash::Hash for Inner {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

impl AsRef<Tbits> for Inner {
    fn as_ref(&self) -> &Tbits {
        &self.0
    }
}

impl AsMut<Tbits> for Inner {
    fn as_mut(&mut self) -> &mut Tbits {
        &mut self.0
    }
}

impl From<Tbits> for Inner {
    fn from(tbits: Tbits) -> Self {
        Self(tbits)
    }
}

impl From<&Inner> for Spongos {
    fn from(inner: &Inner) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl From<Inner> for Spongos {
    fn from(inner: Inner) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl TryFrom<&Spongos> for Inner {
    type Error = ();
    fn try_from(spongos: &Spongos) -> Result<Self, ()> {
        if spongos.is_committed() {
            Ok(spongos.to_inner_tbits().into())
        } else {
            Err(())
        }
    }
}

impl TryFrom<Spongos> for Inner {
    type Error = ();
    fn try_from(spongos: Spongos) -> Result<Self, ()> {
        TryFrom::<&Spongos>::try_from(&spongos)
    }
}

/// Hash (one piece of) data with Spongos.
pub fn hash_data(x: TritSlice, y: TritSliceMut) {
    let mut s = Spongos::init();
    s.absorb(x);
    s.commit();
    s.squeeze(&mut y);
}

/// Hash a concatenation of pieces of data with Spongos.
pub fn hash_datas(xs: &[TritSlice], y: TritSliceMut) {
    let mut s = Spongos::init();
    for x in xs {
        s.absorb(*x);
    }
    s.commit();
    s.squeeze(&mut y);
}
 */

pub trait Hash<TW> {
    /// Hash value size in tbits.
    const HASH_SIZE: usize;

    /// Hash data.
    fn hash(data: TbitSlice<TW>, hash_value: TbitSliceMut<TW>);

    /// Hash data.
    fn hash_tbits(data: Tbits<TW>) -> Tbits<TW> {
        let mut hash_value = Tbits::zero(Self::HASH_SIZE);
        Self::hash(data.slice(), hash_value.slice_mut());
        hash_value
    }

    fn rehash(value: TbitSliceMut<TW>) {
        Self::hash(value.as_const(), value);
    }

    fn rehash_tbits(value: &mut Tbits<TW>) {
        Self::rehash(value.slice_mut());
    }
}

impl<TW, F> Hash<TW> for Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    /// Hash value size in tbits.
    const HASH_SIZE: usize = HASH_SIZE;

    /// Hash data.
    fn hash(data: TbitSlice<TW>, hash_value: TbitSliceMut<TW>);
}

pub fn hash_tbits<TW, F>(data: &Tbits<TW>) -> Tbits<TW>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    let mut s = Spongos::<TW, F>::init();
    s.absorb(data.slice());
    s.commit();
    s.squeeze_tbits(HASH_SIZE)
}

pub fn rehash_tbits<TW, F>(h: &mut Tbits<TW>)
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    let mut s = Spongos::<TW, F>::init();
    s.absorb(h.slice());
    s.commit();
    s.squeeze(&mut h.slice_mut());
}
