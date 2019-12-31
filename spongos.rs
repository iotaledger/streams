use std::fmt;

use crate::trits::{TritConstSlice, TritMutSlice, Trits};
use crate::troika::{Troika};

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
    fn transform(&mut self, outer: &mut TritMutSlice);
}

impl PRP for Troika {
    fn transform(&mut self, outer: &mut TritMutSlice) {
        { // move trits from outer[0..d) to Troika state
            let mut o = outer.as_const().dropped();
            let n = o.size();
            for idx in 0..n {
                self.set1(idx, o.get_trit());
                o = o.drop(1);
            }
            //TODO: should the rest of the outer state be zeroized/padded before permutation?
        }

        self.permutation();
        *outer = outer.pickup_all();

        { // move trits from Troika state to outer[0..rate]
            let mut o = *outer;
            let n = o.size();
            for idx in 0..n {
                o.put_trit(self.get1(idx));
                o = o.drop(1);
            }
        }
    }
}

#[derive(Clone)]
pub struct Spongos {
    /// Spongos transform is Troika.
    s: Troika,
    /// Current position in the outer state.
    pos: usize,
    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    outer: Trits,
}

impl Spongos {
    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub(crate) fn get_inner(&self, mut inner: TritMutSlice) {
        assert_eq!(0, self.pos, "Spongos state is not committed.");
        assert_eq!(CAPACITY, inner.size());

        let n = inner.size();
        for idx in RATE..RATE+n {
            inner.put_trit(self.s.get1(idx));
            inner = inner.drop(1);
        }
    }

    pub(crate) fn from_inner(mut inner: TritConstSlice) -> Self {
        assert_eq!(CAPACITY, inner.size());

        let mut s = Self::init();
        let n = inner.size();
        for idx in RATE..RATE+n {
            s.s.set1(idx, inner.get_trit());
            inner = inner.drop(1);
        }
        s
    }

    /// `outer` must not be assigned to a variable.
    /// It must be used via `self.outer()` as `self.pos` may change
    /// and it must be kept in sync with `outer` object.
    fn outer(&self) -> TritConstSlice {
        assert!(self.outer.size() >= RATE);
        assert!(self.pos <= RATE);
        TritConstSlice::from_trits(&self.outer).drop(self.pos)
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer_mut()` as `self.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    fn outer_mut(&mut self) -> TritMutSlice {
        assert!(self.outer.size() >= RATE);
        assert!(self.pos <= RATE);
        TritMutSlice::from_mut_trits(&mut self.outer).drop(self.pos)
    }

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(RATE < self.pos + n));
        self.pos += n;
        if RATE == self.pos {
            self.commit();
        }
    }

    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Spongos {
            s: Troika::default(),
            pos: 0,
            outer: Trits::zero(RATE),
        }
    }

    /// Absorb a trit slice into Spongos object.
    pub fn absorb(&mut self, mut x: TritConstSlice) {
        while !x.is_empty() {
            let n = x.copy_min(self.outer_mut());
            self.update(n);
            x = x.drop(n);
        }
    }

    /// Absorb Trits.
    pub fn absorb_trits(&mut self, x: &Trits) {
        self.absorb(x.slice())
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, mut y: TritMutSlice) {
        while !y.is_empty() {
            let n = self.outer().copy_min(y);
            self.outer_mut().take(n).set_zero();
            self.update(n);
            y = y.drop(n);
        }
    }

    /// Squeeze Trits.
    pub fn squeeze_trits(&mut self, n: usize) -> Trits {
        let mut y = Trits::zero(n);
        self.squeeze(y.mut_slice());
        y
    }

    /// Encrypt a trit slice with Spongos object.
    /// Input and output slices must either be the same (point to the same memory/trit location) or be non-overlapping.
    pub fn encr(&mut self, mut x: TritConstSlice, mut y: TritMutSlice) {
        while !x.is_empty() {
            let n = if x.is_same(y.as_const()) {
                y.swap_add_min(self.outer_mut())
            } else {
                x.copy_add_min(self.outer_mut(), y)
            };
            self.update(n);
            x = x.drop(n);
            y = y.drop(n);
        }
    }

    /// Encr Trits.
    pub fn encr_trits(&mut self, x: &Trits) -> Trits {
        let mut y = Trits::zero(x.size());
        self.encr(x.slice(), y.mut_slice());
        y
    }

    /// Encr mut Trits.
    pub fn encr_mut_trits(&mut self, x: &mut Trits) {
        self.encr(x.slice(), x.mut_slice());
    }

    /// Decrypt a trit slice with Spongos object.
    /// Input and output slices must either be the same (point to the same memory/trit location) or be non-overlapping.
    pub fn decr(&mut self, mut x: TritConstSlice, mut y: TritMutSlice) {
        while !x.is_empty() {
            let n = if x.is_same(y.as_const()) {
                y.swap_sub_min(self.outer_mut())
            } else {
                x.copy_sub_min(self.outer_mut(), y)
            };
            self.update(n);
            x = x.drop(n);
            y = y.drop(n);
        }
    }

    /// Decr Trits.
    pub fn decr_trits(&mut self, x: &Trits) -> Trits {
        let mut y = Trits::zero(x.size());
        self.decr(x.slice(), y.mut_slice());
        y
    }

    /// Decr mut Trits.
    pub fn decr_mut_trits(&mut self, x: &mut Trits) {
        self.decr(x.slice(), x.mut_slice());
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
        if self.pos != 0 {
            let mut o = self.outer_mut();
            self.s.transform(&mut o);
            self.pos = 0;
        }
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        let mut x = Trits::zero(CAPACITY);
        joinee.squeeze(x.mut_slice());
        self.absorb(x.slice());
    }
}

impl fmt::Debug for Spongos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[{}]", self.pos, self.outer)
    }
}

/// Shortcut for `Spongos::init`.
pub fn init() -> Spongos {
    Spongos::init()
}

/// Hash (one piece of) data with Spongos.
pub fn hash_data(x: TritConstSlice, y: TritMutSlice) {
    let mut s = Spongos::init();
    s.absorb(x);
    s.commit();
    s.squeeze(y);
}

/// Hash a concatenation of pieces of data with Spongos.
pub fn hash_datas(xs: &[TritConstSlice], y: TritMutSlice) {
    let mut s = Spongos::init();
    for x in xs {
        s.absorb(*x);
    }
    s.commit();
    s.squeeze(y);
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

        {
            let mut s = Spongos::init();
            s.absorb(k.slice());
            s.commit();
            s.squeeze(k.mut_slice());
            s.squeeze(p.mut_slice());
            s.squeeze(x.mut_slice());
        }

        {
            let mut s = Spongos::init();
            s.absorb(k.slice());
            s.absorb(p.slice());
            s.commit();
            s.encr(x.slice(), y.mut_slice());
            s.commit();
            s.squeeze(t.mut_slice());
        }

        {
            let mut s = Spongos::init();
            s.absorb(k.slice());
            s.absorb(p.slice());
            s.commit();
            s.decr(y.slice(), z.mut_slice());
            s.commit();
            s.squeeze(u.mut_slice());
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
}

