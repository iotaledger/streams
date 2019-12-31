use crate::spongos::{Spongos};
use crate::trits::{TritConstSlice, TritMutSlice, Trits};

/// Size of a PRNG secret key.
pub const KEY_SIZE: usize = 243;

/// 
#[derive(Clone)]
pub struct PRNG {
    /// PRNG secret key.
    secret_key: Trits,
}

impl PRNG {
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: TritConstSlice) -> Self {
        assert!(secret_key.size() == KEY_SIZE);
        PRNG {
            secret_key: secret_key.clone_trits(),
        }
    }

    /// Create PRNG with Trits.
    pub fn init_trits(secret_key: &Trits) -> Self {
        Self::init(secret_key.slice())
    }

    fn gen_with_s(&self, s: &mut Spongos, nonce: TritConstSlice, rnd: TritMutSlice) {
        //TODO: `dst` Tryte?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        s.absorb(self.secret_key.slice());
        s.absorb(nonce);
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen(&self, nonce: TritConstSlice, rnd: TritMutSlice) {
        //TODO: `dst` Tryte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = Spongos::init();
        self.gen_with_s(&mut s, nonce, rnd);
    }

    /// Generate Trits.
    pub fn gen_trits(&self, nonce: &Trits, n: usize) -> Trits {
        let mut rnd = Trits::zero(n);
        self.gen(nonce.slice(), rnd.mut_slice());
        rnd
    }

    /// Generate randomness with a list of nonces.
    pub fn gens(&self, nonces: &[TritConstSlice], rnd: TritMutSlice) {
        let mut s = Spongos::init();
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a list of nonces.
    pub fn genss(&self, nonces: &[TritConstSlice], rnds: &[TritMutSlice]) {
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

pub fn init(secret_key: TritConstSlice) -> PRNG {
    PRNG::init(secret_key)
}

pub fn init_trits(secret_key: &Trits) -> PRNG {
    PRNG::init_trits(secret_key)
}

pub fn dbg_init_str(secret_key: &str) -> PRNG {
    PRNG::init_trits(&Trits::cycle_str(KEY_SIZE, secret_key))
}

