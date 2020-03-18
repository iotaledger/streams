//! Spongos-base pseudo-random trinary number generator.

use crate::sponge::{spongos::SpongosT, prp::PRP};
use crate::tbits::{word::SpongosTbitWord, TbitSliceT, TbitSliceMutT, TbitsT};

/// Size of a PRNG secret key.
pub const KEY_SIZE: usize = 243;

/// Spongos-based pseudo-random number generator.
#[derive(Clone)]
pub struct Prng<TW, G> {
    /// PRNG secret key.
    secret_key: TbitsT<TW>,
    _phantom: std::marker::PhantomData<G>,
}

impl<TW, G> Prng<TW, G>
where
    TW: SpongosTbitWord,
    G: PRP<TW>,
{
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: TbitsT<TW>) -> Self {
        assert!(secret_key.size() == KEY_SIZE);
        Self {
            secret_key,
            _phantom: std::marker::PhantomData,
        }
    }

    fn gen_with_spongos<'a>(&self, s: &mut SpongosT::<TW, G>, nonce: &[TbitSliceT<'a, TW>], rnds: &mut [TbitSliceMutT<'a, TW>]) {
        //TODO: `dst` Tryte?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        for rnd in rnds {
            s.squeeze(&mut *rnd);
        }
    }
}

impl<TW, G> Prng<TW, G>
where
    TW: SpongosTbitWord,
    G: PRP<TW> + Default,
{
    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen<'a>(&self, nonce: TbitSliceT<'a, TW>, rnd: TbitSliceMutT<'a, TW>) {
        //TODO: `dst` Tryte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = SpongosT::<TW, G>::init();
        self.gen_with_spongos(&mut s, nonce, rnd);
    }

    /// Generate Tbits.
    pub fn gen_tbits(&self, nonce: &TbitsT<TW>, n: usize) -> TbitsT<TW> {
        let mut rnd = TbitsT::zero(n);
        self.gen(nonce.slice(), rnd.slice_mut());
        rnd
    }

    /// Generate randomness with a list of nonces.
    pub fn gens<'a>(&self, nonces: &[TbitSliceT<'a, TW>], mut rnd: TbitSliceMutT<'a, TW>) {
        let mut s = SpongosT::<TW, G>::init();
        s.absorb(self.secret_key.slice());
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        s.squeeze(&mut rnd);
    }
}

/*
pub fn init<'a>(secret_key: TbitSlice<'a>) -> PRNG {
    PRNG::init(secret_key)
}

pub fn init_tbits(secret_key: &Tbits) -> PRNG {
    PRNG::init_tbits(secret_key)
}

//#[cfg(test)]
pub fn dbg_init_str(secret_key: &str) -> PRNG {
    PRNG::init_tbits(&Tbits::cycle_str(KEY_SIZE, secret_key))
}
 */
