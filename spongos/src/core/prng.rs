//! Spongos-based pseudo-random number generator.
use alloc::vec::Vec;

// TODO: REMOVE (also dependency!)
// use generic_array::{ArrayLength, GenericArray};

use generic_array::GenericArray;
use rand::{
    CryptoRng,
    RngCore,
    SeedableRng,
};

use super::{
    prp::PRP,
    spongos::{
        KeyType,
        NonceType,
        Spongos,
    },
};

// TOOD: REMOVE
// use crate::{
//     sponge::{
//         prp::PRP,
//         spongos::{
//             Spongos,
//             KeyType,
//             NonceType,
//         },
//     },
// };

// TODO: REMOVE
// /// Generate cryptographically secure bytes.
// /// Suitable for generating session and ephemeral keys.
// pub fn random_bytes<R, N: ArrayLength<u8>>(rng: &mut R) -> GenericArray<u8, N>
// where
//     R: rand::RngCore + rand::CryptoRng,
// {
//     let mut rnd = GenericArray::default();
//     rng.fill_bytes(rnd.as_mut_slice());
//     rnd
// }

type Nonce = [u8; 16];
type Key = [u8; 32];

// TODO: REMOVE
// #[cfg(feature = "std")]
// /// Generate a random nonce.
// fn random_nonce() -> Nonce {
//     rng().gen()
// }
// #[cfg(feature = "std")]
// /// Generate a random key.
// fn random_key() -> Key {
//     rng().gen()
// }

// #[cfg(all(feature = "std", not(target_os = "espidf")))]
// pub(crate) fn rng() -> rand::rngs::ThreadRng {
//     rand::thread_rng()
// }

// // ESPIDF targets (ESP32 family) have std available through-ESP-IDF but
// // pthread_atfork is not implemented, which is necessary to get the thread handle
// // by rand::thread_rng(). Instead, we use a one-off StdRng instance seeded
// // with `getrandom` (`esp_fill_random`). Given the coldness of this
// // function (at least in streams-channels) in practice this approach has a
// // similar security and performance as ThreadRng.
// #[cfg(all(feature = "std", target_os = "espidf"))]
// pub(crate) fn rng() -> rand::rngs::StdRng {
//     <rand::rngs::StdRng as rand::SeedableRng>::from_entropy()
// }

// TODO: REMOVE
/// Prng fixed key size.
// pub type KeySize<F> = spongos::KeySize<F>;
// pub type KeyType<F> = spongos::KeyType<F>;

// /// Spongos-based pseudo-random number generator.
// #[derive(Clone)]
// pub struct Prng<F> where F: PRP {
//     /// PRNG secret key.
//     secret_key: KeyType<F>,
// }

// impl<F> Prng<F> where F: PRP {
//     /// Create PRNG instance and init with a secret key.
//     fn new(secret_key: KeyType<F>) -> Self {
//         Self {
//             secret_key,
//         }
//     }

//     /// Derive secret key from seed and init PRNG with it.
//     fn from_seed(seed: impl AsRef<[u8]>) -> Self {
//         let mut s = Spongos::<F>::init();
//         let secret_key = s.hash(seed);
//         Self::new(secret_key)
//     }

//     // TODO: PRNG randomness hierarchy via nonce: domain (seed, ed/x25519, session key, etc.), secret, counter.
//     fn gen_with_spongos<'a>(&self, s: &mut Spongos<F>, nonces: &[&'a [u8]], rnds: &mut [&'a mut [u8]]) {
//         // TODO: `dst` byte?
//         // TODO: Reimplement PRNG with DDML?
//         s.absorb(&self.secret_key[..]);
//         for nonce in nonces {
//             s.absorb(nonce);
//         }
//         s.commit();
//         for rnd in rnds {
//             s.squeeze_mut(rnd);
//         }
//     }

//     /// Generate randomness with a unique nonce
//     fn gen_mut(&self, nonce: impl AsRef<[u8]>, mut rnd: impl AsMut<[u8]>) {
//         let mut s = Spongos::<F>::init();
//         self.gen_with_spongos(&mut s, &[nonce.as_ref()], &mut [rnd.as_mut()]);
//     }

//     /// Generate a random collection of bytes
//     pub(crate) fn gen<R>(&self, nonce: impl AsRef<[u8]>) -> R where R: AsMut<[u8]> + Default {
//         let mut r = Default::default();
//         self.gen_mut(nonce, &mut r);
//         r
//     }

//     // TODO: REMOVE
//     // pub fn gen_arr<N: ArrayLength<u8>>(&self, nonce: impl AsRef<[u8]>) -> GenericArray<u8, N> {
//     //     let mut rnd = GenericArray::default();
//     //     self.gen(nonce, &mut rnd);
//     //     rnd
//     // }

//     pub(crate) fn gen_n(&self, nonce: impl AsRef<[u8]>, n: usize) -> Vec<u8> {
//         let mut rnd = vec![0; n];
//         self.gen_mut(nonce, &mut rnd);
//         rnd
//     }
// }

// fn init<G: PRP>(secret_key: KeyType<G>) -> Prng<G> {
//     Prng::new(secret_key)
// }

// pub(crate) fn from_seed<G: PRP>(domain: &str, seed: &str) -> Prng<G> {
//     let mut s = Spongos::<G>::init();
//     s.absorb(seed.as_bytes());
//     s.commit();
//     s.absorb(domain.as_bytes());
//     s.commit();
//     Prng::new(s.squeeze())
// }

// fn dbg_init_str<G: PRP>(secret_key: &str) -> Prng<G> {
//     from_seed("IOTA Streams dbg prng init", secret_key)
// }

// TODO: REMOVE
// /// Rng fixed nonce size.
// pub type NonceSize<F> = spongos::NonceSize<F>;
// // pub type NonceType<F> = spongos::NonceType<F>;
// pub type NonceType = Vec<u8>;

pub struct SpongosRng<F> {
    spongos: Spongos<F>,
    nonce: Nonce,
}

impl<F> SpongosRng<F> {
    pub fn new<T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP + Default,
    {
        let mut spongos = Spongos::<F>::init();
        let key = spongos.sponge(seed);
        Self::from_seed(key)
    }

    fn from_spongos(prng: Spongos<F>, nonce: Nonce) -> Self {
        Self { spongos: prng, nonce }
    }

    fn inc(&mut self) {
        for i in self.nonce.iter_mut() {
            let (r, has_wrapped) = i.overflowing_add(1);
            *i = r;
            if !has_wrapped {
                return;
            }
        }
    }
}

impl<F> RngCore for SpongosRng<F>
where
    F: PRP,
{
    fn next_u32(&mut self) -> u32 {
        // TODO: REMOVE
        // let mut v = [0_u8; 4];
        // self.spongos.gen_mut(&self.nonce[..], &mut v);
        self.inc();
        u32::from_le_bytes(self.spongos.sponge(&self.nonce))
    }
    fn next_u64(&mut self) -> u64 {
        // TODO: REMOVE
        // let mut v = [0_u8; 8];
        // self.spongos.gen_mut(&self.nonce[..], &mut v);
        self.inc();
        u64::from_le_bytes(self.spongos.sponge(&self.nonce))
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inc();
        self.spongos.sponge_mut(&self.nonce, dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<F> CryptoRng for SpongosRng<F> where F: PRP {}

impl<F> SeedableRng for SpongosRng<F>
where
    F: PRP + Default,
{
    type Seed = Key;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut spongos = Spongos::init();
        let nonce = spongos.sponge(seed);
        Self::from_spongos(spongos, nonce)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::core::{
        prp::keccak::KeccakF1600,
        spongos::Spongos,
    };

    use super::SpongosRng;

    #[test]
    fn nonce_incremental_does_not_overflow() {
        let mut rng = SpongosRng::<KeccakF1600>::from_spongos(Spongos::init(), [255; 16]);
        let _random_number: usize = rng.gen();
    }
}
