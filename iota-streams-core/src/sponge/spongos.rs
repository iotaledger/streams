//use std::convert::{AsMut, AsRef, From, TryFrom};
use std::fmt;
//use std::hash;

use super::prp::PRP;
use crate::hash::Hash;
use crate::tbits::{
    word::{BasicTbitWord, SpongosTbitWord},
    TbitSlice, TbitSliceMut, Tbits,
};

/// Implemented as a separate from `Spongos` struct in order to deal with life-times.
#[derive(Clone)]
pub struct Outer<TW> {
    /// Current position in the outer state.
    pos: usize,
    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    tbits: Tbits<TW>,
}

impl<TW> Outer<TW>
where
    TW: BasicTbitWord,
{
    /// Create a new outer state with a given rate (size).
    pub fn new(rate: usize) -> Self {
        Self {
            pos: 0,
            tbits: Tbits::zero(rate),
        }
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer.slice_mut()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    pub fn slice_mut(&mut self) -> TbitSliceMut<TW> {
        //debug_assert!(self.trits.size() >= RATE);
        //debug_assert!(self.pos <= RATE);
        self.tbits.slice_mut().drop(self.pos)
    }

    pub fn slice_min_mut(&mut self, n: usize) -> TbitSliceMut<TW> {
        self.slice_mut().take_min(n)
    }

    /// Rate (total size) of the outer state.
    pub fn rate(&self) -> usize {
        self.tbits.size()
    }

    /// Available size of the outer tbits.
    pub fn size(&self) -> usize {
        self.tbits.size() - self.pos
    }
}

impl<TW> fmt::Debug for Outer<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{:?}]", self.pos, self.tbits)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    OVERWRITE,
    XOR,
}

#[derive(Clone)]
pub struct Spongos<TW, F> {
    /// Spongos transform.
    s: F,
    /// Outer state.
    outer: Outer<TW>,
}

impl<TW, F> Spongos<TW, F>
where
    F: PRP<TW>,
{
    /// Sponge fixed key size.
    pub const KEY_SIZE: usize = F::CAPACITY;

    /// Sponge fixed hash size.
    pub const HASH_SIZE: usize = F::CAPACITY;

    /// Sponge fixed MAC size.
    pub const MAC_SIZE: usize = F::CAPACITY;
}

impl<TW, F> Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }
}

impl<TW, F> Default for Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    fn default() -> Self {
        Self::init()
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
            outer: Outer::new(F::RATE),
        }
    }

    pub fn from_inner(inner: F::Inner) -> Self {
        Self::init_with_state(inner.into())
    }

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(F::RATE < self.outer.pos + n));
        self.outer.pos += n;
        if F::RATE == self.outer.pos {
            self.commit();
        }
    }

    /*
    fn loop_steps<I>(&mut self, mut size: usize, step: I)
        where I: for<'a> FnMut(TbitSliceMut<'a, TW>)
    {
        while size > 0 {
            let n = {
                let s = self.outer.slice_min_mut(size);
                step(s);
                s.size()
            };
            self.update(n);
            size -= n;
        }
    }
     */

    /// Absorb a trit slice into Spongos object.
    pub fn absorb<'a>(&'a mut self, mut x: TbitSlice<'a, TW>) {
        while !x.is_empty() {
            let mut s = self.outer.slice_min_mut(x.size());
            let n = s.size();
            let x_head = x.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.absorb_overwrite(x_head);
            } else {
                s.absorb_xor(x_head);
            }
            self.update(n);
        }
    }

    /// Absorb Tbits.
    pub fn absorb_tbits(&mut self, x: &Tbits<TW>) {
        self.absorb(x.slice())
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, y: &mut TbitSliceMut<TW>) {
        while !y.is_empty() {
            let mut s = self.outer.slice_min_mut(y.size());
            let n = s.size();
            let mut head = y.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.squeeze_overwrite(&mut head);
            } else {
                s.squeeze_xor(&mut head);
            }
            self.update(n);
        }
    }
    /// Squeeze consuming slice `y`.
    pub fn squeeze2(&mut self, mut y: TbitSliceMut<TW>) {
        self.squeeze(&mut y);
    }

    /// Squeeze a trit slice from Spongos object and compare.
    pub fn squeeze_eq(&mut self, mut y: TbitSlice<TW>) -> bool {
        let mut eq = true;
        while !y.is_empty() {
            let mut s = self.outer.slice_min_mut(y.size());
            let n = s.size();
            let head = y.advance(n);
            let eqn = if F::MODE == Mode::OVERWRITE {
                s.squeeze_eq_overwrite(head)
            } else {
                s.squeeze_eq_xor(head)
            };
            // force constant-time equality
            eq = eqn && eq;
            self.update(n);
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
    pub fn encrypt(&mut self, mut x: TbitSlice<TW>, y: &mut TbitSliceMut<TW>) {
        unsafe {
            debug_assert!(!x.is_overlapping(&y.as_const()));
        }
        assert_eq!(x.size(), y.size());
        while !x.is_empty() {
            let mut s = self.outer.slice_min_mut(x.size());
            let n = s.size();
            let x_head = x.advance(n);
            let mut y_head = y.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.encrypt_overwrite(x_head, &mut y_head);
            } else {
                s.encrypt_xor(x_head, &mut y_head);
            }
            self.update(n);
        }
    }
    /// Encrypt consuming slice `y`.
    pub fn encrypt2(&mut self, x: TbitSlice<TW>, mut y: TbitSliceMut<TW>) {
        self.encrypt(x, &mut y);
    }

    /// Encrypt in-place a trit slice with Spongos object.
    pub fn encrypt_mut(&mut self, xy: &mut TbitSliceMut<TW>) {
        while !xy.is_empty() {
            let mut s = self.outer.slice_min_mut(xy.size());
            let n = s.size();
            let mut xy_head = xy.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.encrypt_overwrite_mut(&mut xy_head);
            } else {
                s.encrypt_xor_mut(&mut xy_head);
            }
            self.update(n);
        }
    }
    /// Encrypt consuming slice `xy`.
    pub fn encrypt2_mut(&mut self, mut xy: TbitSliceMut<TW>) {
        self.encrypt_mut(&mut xy);
    }

    /// Encrypt Tbits.
    pub fn encrypt_tbits(&mut self, x: &Tbits<TW>) -> Tbits<TW> {
        let mut y = Tbits::zero(x.size());
        self.encrypt(x.slice(), &mut y.slice_mut());
        y
    }

    /// Encrypt Tbits in-place.
    pub fn encrypt_mut_tbits(&mut self, t: &mut Tbits<TW>) {
        let mut xy = t.slice_mut();
        self.encrypt_mut(&mut xy);
    }

    /// Decrypt a tbit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn decrypt(&mut self, mut y: TbitSlice<TW>, x: &mut TbitSliceMut<TW>) {
        unsafe {
            debug_assert!(!y.is_overlapping(&x.as_const()));
        }
        assert_eq!(x.size(), y.size());
        while !x.is_empty() {
            let mut s = self.outer.slice_min_mut(y.size());
            let n = s.size();
            let y_head = y.advance(n);
            let mut x_head = x.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.decrypt_overwrite(y_head, &mut x_head);
            } else {
                s.decrypt_xor(y_head, &mut x_head);
            }
            self.update(n);
        }
    }
    /// Decrypt consuming slice `x`.
    pub fn decrypt2(&mut self, y: TbitSlice<TW>, mut x: TbitSliceMut<TW>) {
        self.decrypt(y, &mut x);
    }

    /// Decrypt in-place a trit slice with Spongos object.
    pub fn decrypt_mut(&mut self, xy: &mut TbitSliceMut<TW>) {
        while !xy.is_empty() {
            let mut s = self.outer.slice_min_mut(xy.size());
            let n = s.size();
            let mut xy_head = xy.advance(n);
            if F::MODE == Mode::OVERWRITE {
                s.decrypt_overwrite_mut(&mut xy_head);
            } else {
                s.decrypt_xor_mut(&mut xy_head);
            }
            self.update(n);
        }
    }
    /// Decrypt consuming slice `xy`.
    pub fn decrypt2_mut(&mut self, mut xy: TbitSliceMut<TW>) {
        self.decrypt_mut(&mut xy);
    }

    /// Decrypt Tbits.
    pub fn decrypt_tbits(&mut self, x: &Tbits<TW>) -> Tbits<TW> {
        let mut y = Tbits::zero(x.size());
        self.decrypt(x.slice(), &mut y.slice_mut());
        y
    }

    /// Decrypt Tbits in-place.
    pub fn decrypt_mut_tbits(&mut self, t: &mut Tbits<TW>) {
        let mut xy = t.slice_mut();
        self.decrypt_mut(&mut xy);
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
        let mut x = Tbits::zero(F::CAPACITY);
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

    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub fn to_inner(&self) -> F::Inner {
        assert!(self.is_committed());
        self.s.clone().into()
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
 */

/// Hash (one piece of) data with Spongos.
pub fn hash_data<TW, F>(x: TbitSlice<TW>, mut y: TbitSliceMut<TW>)
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    let mut s = Spongos::<TW, F>::init();
    s.absorb(x);
    s.commit();
    s.squeeze(&mut y);
}

/*
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

impl<TW, F> Hash<TW> for Spongos<TW, F>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    /// Hash value size in tbits.
    const HASH_SIZE: usize = F::CAPACITY;

    fn init() -> Self {
        init::<TW, F>()
    }
    fn update(&mut self, data: TbitSlice<TW>) {
        self.absorb(data);
    }
    fn done(&mut self, hash_value: &mut TbitSliceMut<TW>) {
        self.commit();
        self.squeeze(hash_value);
    }

    /// Hash data.
    fn hash(data: TbitSlice<TW>, hash_value: &mut TbitSliceMut<TW>) {
        let mut s = Spongos::<TW, F>::init();
        s.absorb(data);
        s.commit();
        s.squeeze(hash_value);
    }
}

pub fn hash_tbits<TW, F>(data: &Tbits<TW>) -> Tbits<TW>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    let mut s = Spongos::<TW, F>::init();
    s.absorb(data.slice());
    s.commit();
    s.squeeze_tbits(Spongos::<TW, F>::HASH_SIZE)
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
