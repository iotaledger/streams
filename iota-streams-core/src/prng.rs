//! Spongos-base pseudo-random trinary number generator.

use crate::{
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
};

/// Spongos-based pseudo-random number generator.
#[derive(Clone)]
pub struct Prng<G> {
    /// PRNG secret key.
    secret_key: Vec<u8>,
    _phantom: std::marker::PhantomData<G>,
}

fn random_bytes<R>(n: usize, rng: &mut R) -> Vec<u8> where
    R: rand::RngCore,
{
    let mut rnd = vec![0; n];
    rng.fill_bytes(rnd.as_mut_slice());
    rnd
}

pub fn random_nonce(n: usize) -> Vec<u8>
{
    random_bytes::<rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

pub fn random_key(n: usize) -> Vec<u8>
{
    random_bytes::<rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

#[test]
fn test_random_nonce() {
    for n in 1..300 {
        random_nonce(n);
    }
}

impl<G> Prng<G>
where
    G: PRP,
{
    /// Prng fixed key size.
    pub const KEY_SIZE: usize = G::CAPACITY_BITS / 8;
}

//TODO: prng randomness hierarchy: domain (mss, ntru, session key, etc.), secret, counter

impl<G> Prng<G>
where
    G: PRP,
{
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: Vec<u8>) -> Self {
        assert!(secret_key.len() == Self::KEY_SIZE);
        Self {
            secret_key,
            _phantom: std::marker::PhantomData,
        }
    }

    fn gen_with_spongos<'a>(
        &self,
        s: &mut Spongos<G>,
        nonces: &[&'a [u8]],
        rnds: &mut [&'a mut [u8]],
    ) {
        //TODO: `dst` Tryte?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        s.absorb(&self.secret_key[..]);
        for nonce in nonces {
            s.absorb(*nonce);
        }
        s.commit();
        for rnd in rnds {
            s.squeeze(*rnd);
        }
    }
}

impl<G> Prng<G>
where
    G: PRP + Default,
{
    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen(&self, nonce: &[u8], rnd: &mut [u8]) {
        //TODO: `dst` byte?
        //TODO: Implement Sponge?
        //TODO: Reimplement PRNG with Spongos and PB3? Add domain separation string + dst tryte.
        let mut s = Spongos::<G>::init();
        self.gen_with_spongos(&mut s, &[nonce], &mut [rnd]);
    }

    /// Generate Tbits.
    pub fn gen_bytes(&self, nonce: &Vec<u8>, n: usize) -> Vec<u8> {
        let mut rnd = vec![0; n];
        self.gen(&nonce[..], &mut rnd[..]);
        rnd
    }
}

//#[cfg(test)]
pub fn dbg_init_str<G>(secret_key: &str) -> Prng<G>
where
    G: PRP,
{
    panic!("not implemented");
    //Prng::init(Tbits::cycle_str(Prng::<G>::KEY_SIZE, secret_key))
}
