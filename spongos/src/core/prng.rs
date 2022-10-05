//! Spongos-based pseudo-random number generator.
use rand::{CryptoRng, RngCore, SeedableRng};

use super::{
    prp::{keccak::KeccakF1600, PRP},
    spongos::Spongos,
};

type Nonce = [u8; 16];
type Key = [u8; 32];

/// Spongos-based psuedo-random number generator.
pub struct SpongosRng<F = KeccakF1600> {
    /// Inner [`Spongos`] state
    spongos: Spongos<F>,
    nonce: Nonce,
}

impl<F> SpongosRng<F> {
    /// Creates a new [`SpongosRng`] from an explicit byte array. A new [`Spongos`] object is
    /// created, and is used to sponge the seed into a new `Key`. This `Key` is then used as a
    /// seed to generate a new [`SpongosRng`].
    ///
    /// # Arguments
    /// * `seed`: A unique byte array
    pub fn new<T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP + Default,
    {
        let mut spongos = Spongos::<F>::init();
        let key = spongos.sponge(seed);
        Self::from_seed(key)
    }

    /// Creates a new [`SpongosRng`] from an explicit [`Spongos`] state and [`Nonce`].
    fn from_spongos(prng: Spongos<F>, nonce: Nonce) -> Self {
        Self { spongos: prng, nonce }
    }

    /// Increments the inner nonce
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
        self.inc();
        u32::from_le_bytes(self.spongos.sponge(&self.nonce))
    }
    fn next_u64(&mut self) -> u64 {
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

    use crate::core::{prp::keccak::KeccakF1600, spongos::Spongos};

    use super::SpongosRng;

    #[test]
    fn nonce_incremental_does_not_overflow() {
        let mut rng = SpongosRng::<KeccakF1600>::from_spongos(Spongos::init(), [255; 16]);
        let _random_number: usize = rng.gen();
    }
}
