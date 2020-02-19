//! Spongos-base pseudo-random trinary number generator.

use crate::spongos::Spongos;
use crate::trits::{TritSlice, TritSliceMut, Trits};

/// Size of a PRNG secret key.
pub const KEY_SIZE: usize = 243;

/// Spongos-based pseudo-random trinary number generator.
#[derive(Clone)]
pub struct PRNG {
    /// PRNG secret key.
    secret_key: Trits,
}

impl PRNG {
    /// Create PRNG instance and init with a secret key.
    pub fn init<'a>(secret_key: TritSlice<'a>) -> Self {
        assert!(secret_key.size() == KEY_SIZE);
        PRNG {
            secret_key: secret_key.clone_trits(),
        }
    }

    /// Create PRNG with Trits.
    pub fn init_trits(secret_key: &Trits) -> Self {
        Self::init(secret_key.slice())
    }

    fn gen_with_s<'a>(&self, s: &mut Spongos, nonce: TritSlice<'a>, rnd: TritSliceMut<'a>) {
        //TODO: `dst` Tryte?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        s.absorb(self.secret_key.slice());
        s.absorb(nonce);
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen<'a>(&self, nonce: TritSlice<'a>, rnd: TritSliceMut<'a>) {
        //TODO: `dst` Tryte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = Spongos::init();
        self.gen_with_s(&mut s, nonce, rnd);
    }

    /// Generate Trits.
    pub fn gen_trits(&self, nonce: &Trits, n: usize) -> Trits {
        let mut rnd = Trits::zero(n);
        self.gen(nonce.slice(), rnd.slice_mut());
        rnd
    }

    /// Generate randomness with a list of nonces.
    pub fn gens<'a>(&self, nonces: &[TritSlice<'a>], rnd: TritSliceMut<'a>) {
        let mut s = Spongos::init();
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a list of nonces.
    pub fn genss<'a>(&self, nonces: &[TritSlice<'a>], rnds: &[TritSliceMut<'a>]) {
        let mut s = Spongos::init();
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        for rnd in rnds {
            s.squeeze(*rnd);
        }
    }
}

pub fn init<'a>(secret_key: TritSlice<'a>) -> PRNG {
    PRNG::init(secret_key)
}

pub fn init_trits(secret_key: &Trits) -> PRNG {
    PRNG::init_trits(secret_key)
}

//#[cfg(test)]
pub fn dbg_init_str(secret_key: &str) -> PRNG {
    PRNG::init_trits(&Trits::cycle_str(KEY_SIZE, secret_key))
}
