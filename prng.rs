use crate::trits::*;
use crate::spongos::*;

/// Size of a PRNG secret key.
pub const MAM_PRNG_SECRET_KEY_SIZE: usize = 243;

#[derive(Clone)]
pub struct PRNG<TW> {
    /// PRNG secret key.
    secret_key: Trits<TW>,
}

impl<TW> PRNG<TW> where TW: TritWord + Copy {
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: TritConstSlice<TW>) -> Self {
        assert!(secret_key.size() == MAM_PRNG_SECRET_KEY_SIZE);
        PRNG {
            secret_key: secret_key.clone_trits(),
        }
    }

    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen(&self, nonce: TritConstSlice<TW>, rnd: TritMutSlice<TW>) {
        //TODO: `dst` Tryte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = Spongos::<TW>::init();
        s.absorb(self.secret_key.slice());
        s.absorb(nonce);
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a list of nonces.
    pub fn gens(&self, nonces: &[TritConstSlice<TW>], rnd: TritMutSlice<TW>) {
        let mut s = Spongos::<TW>::init();
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        s.squeeze(rnd);
    }

    /// Generate randomness with a list of nonces.
    pub fn genss(&self, nonces: &[TritConstSlice<TW>], rnds: &[TritMutSlice<TW>]) {
        let mut s = Spongos::<TW>::init();
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
