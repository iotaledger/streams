//! Spongos-based pseudo-random number generator.

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

/// Generate cryptographically secure bytes.
/// Suitable for generating session and ephemeral keys.
fn random_bytes<R>(n: usize, rng: &mut R) -> Vec<u8> where
    R: rand::RngCore + rand::CryptoRng,
{
    let mut rnd = vec![0; n];
    rng.fill_bytes(rnd.as_mut_slice());
    rnd
}

/// Generate a random nonce.
pub fn random_nonce(n: usize) -> Vec<u8>
{
    random_bytes::<rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

/// Generate a random key.
pub fn random_key(n: usize) -> Vec<u8>
{
    random_bytes::<rand::rngs::ThreadRng>(n, &mut rand::thread_rng())
}

impl<G: PRP> Prng<G>
{
    /// Prng fixed key size.
    pub const KEY_SIZE: usize = G::CAPACITY_BITS / 8;

    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: Vec<u8>) -> Self {
        assert!(secret_key.len() == Self::KEY_SIZE);
        Self {
            secret_key,
            _phantom: std::marker::PhantomData,
        }
    }

    //TODO: prng randomness hierarchy via nonce: domain (mss, ntru, session key, etc.), secret, counter
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

pub fn init<G: PRP>(secret_key: Vec<u8>) -> Prng<G>
{
    Prng::init(secret_key)
}

pub fn dbg_init_str<G: PRP>(secret_key: &str) -> Prng<G>
{
    let mut s = Spongos::<G>::init();
    s.absorb(secret_key.as_bytes());
    s.commit();
    let r = Prng::init(s.squeeze_buf(Prng::<G>::KEY_SIZE));
    r
}

pub struct Rng<G> {
    prng: Prng<G>,
    nonce: Vec<u8>,
}

impl<G> Rng<G> {
    pub fn new(prng: Prng<G>, nonce: Vec<u8>) -> Self {
        Self {
            prng,
            nonce,
        }
    }
    fn inc(&mut self) {
        //TODO: inc nonce
    }
}

impl<G: PRP> rand::RngCore for Rng<G>
{
    fn next_u32(&mut self) -> u32 {
        let mut v = [0_u8; 4];
        self.prng.gen(&self.nonce[..], &mut v);
        self.inc();
        //TODO: use transmute
        0
            | ((v[3] as u32) << 24)
            | ((v[2] as u32) << 16)
            | ((v[1] as u32) <<  8)
            | ((v[0] as u32) <<  0)
    }
    fn next_u64(&mut self) -> u64 {
        let mut v = [0_u8; 8];
        self.prng.gen(&self.nonce[..], &mut v);
        self.inc();
        //TODO: use transmute
        0
            | ((v[7] as u64) << 56)
            | ((v[6] as u64) << 48)
            | ((v[5] as u64) << 40)
            | ((v[4] as u64) << 32)
            | ((v[3] as u64) << 24)
            | ((v[2] as u64) << 16)
            | ((v[1] as u64) <<  8)
            | ((v[0] as u64) <<  0)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.prng.gen(&self.nonce[..], dest);
        self.inc();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<G: PRP> rand::CryptoRng for Rng<G> {}
