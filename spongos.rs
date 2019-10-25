use crate::trits::*;
use crate::troika::*;

/// Rate -- size of outer part of the Spongos state.
pub const SPONGOS_RATE: usize = 486;

/// Capacity -- size of inner part of the Spongos state.
pub const SPONGOS_CAPACITY: usize = 243;

/// Width -- size of the Spongos state.
pub const SPONGOS_WIDTH: usize = SPONGOS_RATE + SPONGOS_CAPACITY;

/// Sponge fixed key size.
pub const KEY_SIZE: usize = 243;

/// Sponge fixed hash size.
pub const HASH_SIZE: usize = 243;

/// Sponge fixed MAC size.
pub const MAC_SIZE: usize = 243;

trait PRP<TW> {
    fn transform(&mut self, outer: &mut TritMutSlice<TW>);
}

impl<TW> PRP<TW> for Troika where TW: TritWord + Copy {
    fn transform(&mut self, outer: &mut TritMutSlice<TW>) {
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
pub struct Spongos<TW> {
    /// Spongos transform is Troika.
    s: Troika,
    /// Current position in the outer state.
    pos: usize,
    /// Outer state is stored externally due to Troika implementation.
    /// It is injected into Troika state before transform and extracted after.
    outer: Trits<TW>,
}

impl<TW> Spongos<TW> where TW: TritWord + Copy {
    /// `outer` must not be assigned to a variable.
    /// It must be used via `self.outer()` as `self.pos` may change
    /// and it must be kept in sync with `outer` object.
    fn outer(&self) -> TritConstSlice<TW> {
        assert!(self.outer.size() >= SPONGOS_RATE);
        assert!(self.pos <= SPONGOS_RATE);
        TritConstSlice::from_trits(&self.outer).drop(self.pos)
    }

    /// `outer_mut` must not be assigned to a variable.
    /// It must be used via `self.outer_mut()` as `self.pos` may change
    /// and it must be kept in sync with `outer_mut` object.
    fn outer_mut(&mut self) -> TritMutSlice<TW> {
        assert!(self.outer.size() >= SPONGOS_RATE);
        assert!(self.pos <= SPONGOS_RATE);
        TritMutSlice::from_mut_trits(&mut self.outer).drop(self.pos)
    }

    /// Update Spongos after processing the current piece of data of `n` trits.
    fn update(&mut self, n: usize) {
        assert!(!(SPONGOS_RATE < self.pos + n));
        self.pos += n;
        if SPONGOS_RATE == self.pos {
            self.commit();
        }
    }

    /// Create a Spongos object, initialize state with zero trits.
    pub fn init() -> Self {
        Spongos {
            s: Troika::default(),
            pos: 0,
            outer: Trits::zero(SPONGOS_RATE),
        }
    }

    /// Absorb a trit slice into Spongos object.
    pub fn absorb(&mut self, mut x: TritConstSlice<TW>) {
        while !x.is_empty() {
            let n = x.copy_min(self.outer_mut());
            self.update(n);
            x = x.drop(n);
        }
    }

    /// Squeeze a trit slice from Spongos object.
    pub fn squeeze(&mut self, mut y: TritMutSlice<TW>) {
        while !y.is_empty() {
            let n = self.outer().copy_min(y);
            self.outer_mut().take(n).set_zero();
            self.update(n);
            y = y.drop(n);
        }
    }

    /// Encrypt a trit slice with Spongos object.
    /// Input and output slices must either be the same (point to the same memory/trit location) or be non-overlapping.
    pub fn encr(&mut self, mut x: TritConstSlice<TW>, mut y: TritMutSlice<TW>) {
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

    /// Decrypt a trit slice with Spongos object.
    /// Input and output slices must either be the same (point to the same memory/trit location) or be non-overlapping.
    pub fn decr(&mut self, mut x: TritConstSlice<TW>, mut y: TritMutSlice<TW>) {
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

    /// Fork Spongos object into another.
    /// Essentially this just creates a copy of self.
    pub fn fork(&self, fork: &mut Self) {
        fork.clone_from(self);
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
        let mut x = Trits::<TW>::zero(SPONGOS_CAPACITY);
        joinee.squeeze(x.mut_slice());
        self.absorb(x.slice());
    }
}

/// Hash (one piece of) data with Spongos.
pub fn hash_data<TW>(x: TritConstSlice<TW>, y: TritMutSlice<TW>) where TW: TritWord + Copy {
    let mut s = Spongos::<TW>::init();
    s.absorb(x);
    s.commit();
    s.squeeze(y);
}

/// Hash a concatenation of pieces of data with Spongos.
pub fn hash_datas<TW>(xs: &[TritConstSlice<TW>], y: TritMutSlice<TW>) where TW: TritWord + Copy {
    let mut s = Spongos::<TW>::init();
    for x in xs {
        s.absorb(*x);
    }
    s.commit();
    s.squeeze(y);
}

#[cfg(test)]
mod test_spongos {
    use super::*;

    fn test_spongosn(n: usize) {
        let mut k = Trits::<Trit>::zero(n);
        let mut p = Trits::<Trit>::zero(n);
        let mut x = Trits::<Trit>::zero(n);
        let mut y = Trits::<Trit>::zero(n);
        let mut z = Trits::<Trit>::zero(n);
        let mut t = Trits::<Trit>::zero(n);
        let mut u = Trits::<Trit>::zero(n);

        {
            let mut s = Spongos::<Trit>::init();
            s.absorb(k.slice());
            s.commit();
            s.squeeze(k.mut_slice());
            s.squeeze(p.mut_slice());
            s.squeeze(x.mut_slice());
        }

        {
            let mut s = Spongos::<Trit>::init();
            s.absorb(k.slice());
            s.absorb(p.slice());
            s.commit();
            s.encr(x.slice(), y.mut_slice());
            s.commit();
            s.squeeze(t.mut_slice());
        }

        {
            let mut s = Spongos::<Trit>::init();
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
    fn test_spongos() {
        for i in 1..100 {
            test_spongosn(i);
        }
        test_spongosn(SPONGOS_RATE / 2 - 1);
        test_spongosn(SPONGOS_RATE / 2);
        test_spongosn(SPONGOS_RATE / 2 + 1);
        test_spongosn(SPONGOS_RATE - 1);
        test_spongosn(SPONGOS_RATE);
        test_spongosn(SPONGOS_RATE + 1);
        test_spongosn(SPONGOS_RATE * 2);
        test_spongosn(SPONGOS_RATE * 5);
    }
}

