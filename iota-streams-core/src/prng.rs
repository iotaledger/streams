//! Spongos-base pseudo-random trinary number generator.

use crate::{
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
    tbits::{
        binary::Byte,
        convert::IConvertOnto,
        word::{
            RngTbitWord,
            SpongosTbitWord,
            StringTbitWord,
        },
        TbitSlice,
        TbitSliceMut,
        Tbits,
    },
};

/// Spongos-based pseudo-random number generator.
#[derive(Clone)]
pub struct Prng<TW, G> {
    /// PRNG secret key.
    secret_key: Tbits<TW>,
    _phantom: std::marker::PhantomData<G>,
}

fn random_tbits<TW, R>(n: usize, rng: &mut R) -> Tbits<TW>
where
    //TW: BasicTbitWord,
    //Byte: ConvertOnto<TW>,
    TW: RngTbitWord,
    R: rand::RngCore,
{
    let mut random_bytes = vec![Byte(0); n];
    rng.fill_bytes(unsafe { std::mem::transmute::<&mut [Byte], &mut [u8]>(random_bytes.as_mut_slice()) });
    let bytes = TbitSlice::<Byte>::from_slice(n * 8, random_bytes.as_slice());
    let mut tbits = Tbits::<TW>::zero(n);
    <TW as IConvertOnto<Byte>>::icvt_onto(bytes, &mut tbits.slice_mut());
    tbits
}

pub fn random_nonce<TW>(n: usize) -> Tbits<TW>
where
    TW: RngTbitWord,
{
    random_tbits::<TW, rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

pub fn random_key<TW>(n: usize) -> Tbits<TW>
where
    TW: RngTbitWord,
{
    random_tbits::<TW, rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

#[test]
fn test_random_nonce() {
    use crate::tbits::trinary::Trit;
    for n in 1..300 {
        random_nonce::<Trit>(n);
        random_nonce::<Byte>(n);
    }
}

impl<TW, G> Prng<TW, G>
where
    G: PRP<TW>,
{
    /// Prng fixed key size.
    pub const KEY_SIZE: usize = G::CAPACITY;
}

//TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter

impl<TW, G> Prng<TW, G>
where
    TW: SpongosTbitWord,
    G: PRP<TW>,
{
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: Tbits<TW>) -> Self {
        assert!(secret_key.size() == Self::KEY_SIZE);
        Self {
            secret_key,
            _phantom: std::marker::PhantomData,
        }
    }

    fn gen_with_spongos<'a>(
        &self,
        s: &mut Spongos<TW, G>,
        nonces: &[TbitSlice<'a, TW>],
        rnds: &mut [&mut TbitSliceMut<'a, TW>],
    ) {
        //TODO: `dst` Tryte?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
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

impl<TW, G> Prng<TW, G>
where
    TW: SpongosTbitWord,
    G: PRP<TW> + Default,
{
    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen<'a>(&self, nonce: TbitSlice<'a, TW>, rnd: &mut TbitSliceMut<'a, TW>) {
        //TODO: `dst` Tryte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = Spongos::<TW, G>::init();
        self.gen_with_spongos(&mut s, &[nonce], &mut [rnd]);
    }
    /// Gen consuming slice `rnd`.
    pub fn gen2<'a>(&self, nonce: TbitSlice<'a, TW>, mut rnd: TbitSliceMut<'a, TW>) {
        self.gen(nonce, &mut rnd);
    }

    /// Generate Tbits.
    pub fn gen_tbits(&self, nonce: &Tbits<TW>, n: usize) -> Tbits<TW> {
        let mut rnd = Tbits::zero(n);
        self.gen(nonce.slice(), &mut rnd.slice_mut());
        rnd
    }

    /// Generate randomness with a list of nonces.
    pub fn gens<'a>(&self, nonces: &[TbitSlice<'a, TW>], mut rnd: TbitSliceMut<'a, TW>) {
        let mut s = Spongos::<TW, G>::init();
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

 */

//#[cfg(test)]
pub fn dbg_init_str<TW, G>(secret_key: &str) -> Prng<TW, G>
where
    TW: StringTbitWord + SpongosTbitWord,
    G: PRP<TW>,
{
    Prng::init(Tbits::cycle_str(Prng::<TW, G>::KEY_SIZE, secret_key))
}
