use std::fmt;
use std::hash;
use std::str::FromStr;
use std::convert::{AsRef, AsMut, From, TryFrom};

use crate::trits::{defs::{Trit}, TritSlice, TritSliceMut, Trits};
use crate::troika::Troika;

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

trait PRP {
    fn transform(&mut self, outer: &mut TritSliceMut);
}

impl PRP for Troika {
    fn transform(&mut self, outer: &mut TritSliceMut) {
        {
            // move trits from outer[0..d) to Troika state
            let mut o = outer.as_const().dropped();
            let n = o.size();
            for idx in 0..n {
                self.set1(idx, o.get_trit().0);
                o = o.drop(1);
            }
            //TODO: should the rest of the outer state be zeroized/padded before permutation?
        }

        self.permutation();
        *outer = outer.pickup_all();

        {
            // move trits from Troika state to outer[0..rate]
            let mut o = *outer;
            let n = o.size();
            for idx in 0..n {
                o.put_trit(Trit(self.get1(idx)));
                o = o.drop(1);
            }
        }
    }
}

/// Implemented as a separate from `Spongos` struct in order to deal with life-times.
#[derive(Clone)]
struct Outer {
    /// Current position in the outer state.
    pos: usize,
    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    trits: Trits,
}

impl Outer {
    /// `outer` must not be assigned to a variable.
    /// It must be used via `self.outer.slice()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer` object.
    fn slice(&self) -> TritSlice {
        debug_assert!(self.trits.size() >= RATE);
        debug_assert!(self.pos <= RATE);
        self.trits.slice().drop(self.pos)
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer.slice_mut()` as `self.outer.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    fn slice_mut(&mut self) -> TritSliceMut {
        assert!(self.trits.size() >= RATE);
        assert!(self.pos <= RATE);
        self.trits.slice_mut().drop(self.pos)
    }
}

impl fmt::Debug for Outer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{}]", self.pos, self.trits)
    }
}

#[derive(Clone)]
pub struct Spongos {
    /// Spongos transform is Troika.
    s: Troika,
    /// Outer state.
    outer: Outer,
}

impl Spongos {
    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub fn to_inner(&self, mut inner: TritSliceMut) {
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

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(RATE < self.outer.pos + n));
        self.outer.pos += n;
        if RATE == self.outer.pos {
            self.commit();
        }
    }

    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Spongos {
            s: Troika::default(),
            outer: Outer {
                pos: 0,
                trits: Trits::zero(RATE),
            },
        }
    }

    /// Absorb a trit slice into Spongos object.
    pub fn absorb(&mut self, mut x: TritSlice) {
        while !x.is_empty() {
            let n = x.copy_min(self.outer.slice_mut());
            self.update(n);
            x = x.drop(n);
        }
    }

    /// Absorb Trits.
    pub fn absorb_trits(&mut self, x: &Trits) {
        self.absorb(x.slice())
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, mut y: TritSliceMut) {
        while !y.is_empty() {
            let n = self.outer.slice().copy_min(y);
            self.outer.slice_mut().take(n).set_zero();
            self.update(n);
            y = y.drop(n);
        }
    }

    /// Squeeze a trit slice from Spongos object and compare.
    pub fn squeeze_eq(&mut self, mut y: TritSlice) -> bool {
        let mut eq = true;
        while !y.is_empty() {
            // force constant-time equality
            let (eqn, n) = self.outer.slice().eq_min(y);
            eq = eqn && eq;
            self.outer.slice_mut().take(n).set_zero();
            self.update(n);
            y = y.drop(n);
        }
        eq
    }

    /// Squeeze Trits.
    pub fn squeeze_trits(&mut self, n: usize) -> Trits {
        let mut y = Trits::zero(n);
        self.squeeze(y.slice_mut());
        y
    }

    /// Squeeze Trits and compare.
    pub fn squeeze_eq_trits(&mut self, y: &Trits) -> bool {
        self.squeeze_eq(y.slice())
    }

    /// Encrypt a trit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn encr(&mut self, mut x: TritSlice, mut y: TritSliceMut) {
        debug_assert!(!x.is_overlapped(y.as_const()));
        while !x.is_empty() {
            let n = x.copy_add_min(self.outer.slice_mut(), y);
            self.update(n);
            x = x.drop(n);
            y = y.drop(n);
        }
    }

    /// Encrypt in-place a trit slice with Spongos object.
    pub fn encr_mut(&mut self, mut xy: TritSliceMut) {
        while !xy.is_empty() {
            let n = xy.swap_add_min(self.outer.slice_mut());
            self.update(n);
            xy = xy.drop(n);
        }
    }

    /// Encr Trits.
    pub fn encr_trits(&mut self, x: &Trits) -> Trits {
        let mut y = Trits::zero(x.size());
        self.encr(x.slice(), y.slice_mut());
        y
    }

    /// Encr mut Trits.
    pub fn encr_mut_trits(&mut self, t: &mut Trits) {
        let xy = t.slice_mut();
        self.encr_mut(xy);
    }

    /// Decrypt a trit slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    pub fn decr(&mut self, mut x: TritSlice, mut y: TritSliceMut) {
        while !x.is_empty() {
            let n = if x.is_same(y.as_const()) {
                y.swap_sub_min(self.outer.slice_mut())
            } else {
                x.copy_sub_min(self.outer.slice_mut(), y)
            };
            self.update(n);
            x = x.drop(n);
            y = y.drop(n);
        }
    }

    pub fn decr_mut(&mut self, mut xy: TritSliceMut) {
        while !xy.is_empty() {
            let n = xy.swap_sub_min(self.outer.slice_mut());
            self.update(n);
            xy = xy.drop(n);
        }
    }

    /// Decr Trits.
    pub fn decr_trits(&mut self, x: &Trits) -> Trits {
        let mut y = Trits::zero(x.size());
        self.decr(x.slice(), y.slice_mut());
        y
    }

    /// Decr mut Trits.
    pub fn decr_mut_trits(&mut self, t: &mut Trits) {
        let xy = t.slice_mut();
        self.decr_mut(xy);
    }

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
        let mut x = Trits::zero(CAPACITY);
        joinee.squeeze(x.slice_mut());
        self.absorb(x.slice());
    }
}

impl fmt::Debug for Spongos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.outer)
    }
}

/// Shortcut for `Spongos::init`.
pub fn init() -> Spongos {
    Spongos::init()
}

/// Size of inner state.
pub const INNER_SIZE: usize = CAPACITY;

/// Convenience wrapper for storing Spongos inner state.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Inner(Trits);

impl Default for Inner {
    fn default() -> Self {
        Self(Trits::zero(INNER_SIZE))
    }
}

impl hash::Hash for Inner {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

impl AsRef<Trits> for Inner {
    fn as_ref(&self) -> &Trits {
        &self.0
    }
}

impl AsMut<Trits> for Inner {
    fn as_mut(&mut self) -> &mut Trits {
        &mut self.0
    }
}

impl From<Trits> for Inner {
    fn from(trits: Trits) -> Self {
        Self(trits)
    }
}

impl From<&Inner> for Spongos {
    fn from(inner: &Inner) -> Self {
        Self::from_inner_trits(inner.as_ref())
    }
}

impl From<Inner> for Spongos {
    fn from(inner: Inner) -> Self {
        Self::from_inner_trits(inner.as_ref())
    }
}

impl TryFrom<&Spongos> for Inner {
    type Error = ();
    fn try_from(spongos: &Spongos) -> Result<Self, ()> {
        if spongos.is_committed() {
            Ok(spongos.to_inner_trits().into())
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
    s.squeeze(y);
}

/// Hash a concatenation of pieces of data with Spongos.
pub fn hash_datas(xs: &[TritSlice], y: TritSliceMut) {
    let mut s = Spongos::init();
    for x in xs {
        s.absorb(*x);
    }
    s.commit();
    s.squeeze(y);
}

pub fn hash_trits(data: &mut Trits) -> Trits {
    let mut s = Spongos::init();
    s.absorb(data.slice());
    s.commit();
    s.squeeze_trits(HASH_SIZE)
}

pub fn rehash_trits(h: &mut Trits) {
    let mut s = Spongos::init();
    s.absorb(h.slice());
    s.commit();
    s.squeeze(h.slice_mut());
}

#[cfg(test)]
mod test {
    use super::*;

    fn trits_spongosn(n: usize) {
        let mut rng = Spongos::init();
        rng.absorb_trits(&Trits::zero(n));
        rng.commit();
        let k = rng.squeeze_trits(n);
        let p = rng.squeeze_trits(n);
        let x = rng.squeeze_trits(n);
        let y: Trits;
        let mut z: Trits;
        let t: Trits;
        let u: Trits;

        {
            let mut s = Spongos::init();
            s.absorb_trits(&k);
            s.absorb_trits(&p);
            s.commit();
            y = s.encr_trits(&x);
            s.commit();
            t = s.squeeze_trits(n);
        }

        {
            let mut s = Spongos::init();
            s.absorb_trits(&k);
            s.absorb_trits(&p);
            s.commit();
            z = y;
            s.decr_mut_trits(&mut z);
            s.commit();
            u = s.squeeze_trits(n);
        }

        assert!(x == z, "{}: x != D(E(x))", n);
        assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
    }

    fn slice_spongosn(n: usize) {
        let mut k = Trits::zero(n);
        let mut p = Trits::zero(n);
        let mut x = Trits::zero(n);
        let mut y = Trits::zero(n);
        let mut z = Trits::zero(n);
        let mut t = Trits::zero(n);
        let mut u = Trits::zero(n);

        let mut s: Spongos;
        {
            s = Spongos::init();
            s.absorb(k.slice());
            s.commit();
            s.squeeze(k.slice_mut());
            s.squeeze(p.slice_mut());
            s.squeeze(x.slice_mut());
        }

        {
            s = Spongos::init();
            s.absorb(k.slice());
            s.absorb(p.slice());
            s.commit();
            s.encr(x.slice(), y.slice_mut());
            s.commit();
            s.squeeze(t.slice_mut());
        }

        {
            s = Spongos::init();
            s.absorb(k.slice());
            s.absorb(p.slice());
            s.commit();
            s.decr(y.slice(), z.slice_mut());
            s.commit();
            s.squeeze(u.slice_mut());
        }

        assert!(x == z, "{}: x != D(E(x))", n);
        assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
    }

    #[test]
    fn trits_with_size_boundary_cases() {
        for i in 1..100 {
            trits_spongosn(i);
        }
        trits_spongosn(RATE / 2 - 1);
        trits_spongosn(RATE / 2);
        trits_spongosn(RATE / 2 + 1);
        trits_spongosn(RATE - 1);
        trits_spongosn(RATE);
        trits_spongosn(RATE + 1);
        trits_spongosn(RATE * 2);
        trits_spongosn(RATE * 5);
    }

    #[test]
    fn slices_with_size_boundary_cases() {
        for i in 1..100 {
            slice_spongosn(i);
        }
        slice_spongosn(RATE / 2 - 1);
        slice_spongosn(RATE / 2);
        slice_spongosn(RATE / 2 + 1);
        slice_spongosn(RATE - 1);
        slice_spongosn(RATE);
        slice_spongosn(RATE + 1);
        slice_spongosn(RATE * 2);
        slice_spongosn(RATE * 5);
    }

    fn encr_decr_n(n: usize) {
        let mut s = Spongos::init();
        s.absorb_trits(&Trits::cycle_str(KEY_SIZE, "KEY"));
        s.commit();

        let x = Trits::cycle_str(n, "TEXT");
        {
            let mut s2 = s.clone();
            let mut s3 = s.clone();
            let mut s4 = s.clone();

            let ex = s.encr_trits(&x);
            s.commit();
            let tag = s.squeeze_trits(RATE);

            let dex = s2.decr_trits(&ex);
            assert_eq!(x, dex);
            s2.commit();
            assert_eq!(tag, s2.squeeze_trits(RATE));

            let mut x2 = x.clone();
            s3.encr_mut_trits(&mut x2);
            assert_eq!(ex, x2);
            s3.commit();
            assert_eq!(tag, s3.squeeze_trits(RATE));

            s4.decr_mut_trits(&mut x2);
            assert_eq!(x, x2);
            s4.commit();
            assert_eq!(tag, s4.squeeze_trits(RATE));
        }
    }
    #[test]
    fn encr_decr() {
        encr_decr_n(27);
        encr_decr_n(RATE);
        encr_decr_n(RATE - 28);
        encr_decr_n(RATE + 28);
        encr_decr_n(2 * RATE);
    }

    #[test]
    fn inner() {
        let mut s = Spongos::init();
        s.absorb_trits(&Trits::from_str("ABC").unwrap());
        s.commit();
        let mut s2 = Spongos::from_inner_trits(&s.to_inner_trits());

        s.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
        s.commit();
        s2.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
        s2.commit();
        assert_eq!(s.squeeze_trits(RATE + 1), s2.squeeze_trits(RATE + 1));
    }
}
