use crate::signature::ed25519;
use iota_streams_core::Result;

use curve25519_dalek::edwards;
use ed25519_dalek::ExpandedSecretKey;
use iota_streams_core::{
    err,
    prelude::{
        HashSet,
        Vec,
    },
    Errors::KeyConversionFailure,
};
pub use x25519_dalek::{
    EphemeralSecret,
    PublicKey,
    SharedSecret,
    StaticSecret,
};

pub const PUBLIC_KEY_LENGTH: usize = 32;
// pub type PublicKeySize = U32;

pub fn keypair_from_ed25519(kp: &ed25519::Keypair) -> (StaticSecret, PublicKey) {
    // PublicKey is derived from `ExpandedSecretKey`
    let mut key = [0_u8; 32];
    key.copy_from_slice(&ExpandedSecretKey::from(&kp.secret).to_bytes()[..32]);
    let sk = StaticSecret::from(key);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

pub fn public_from_ed25519(pk: &ed25519::PublicKey) -> Result<PublicKey> {
    // `pk.to_bytes` returns Y coordinate
    // try reconstruct X,Y,Z,T coordinates of `EdwardsPoint`
    match edwards::CompressedEdwardsY(pk.to_bytes()).decompress() {
        Some(compressed_edwards) => {
            // pk is a valid `PublicKey` hence contains valid `EdwardsPoint`
            // x25519 uses Montgomery form, and `PublicKey` is just a `MontgomeryPoint`
            Ok(PublicKey::from(compressed_edwards.to_montgomery().to_bytes()))
        }
        None => err!(KeyConversionFailure)?,
    }
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKeyWrap(pub PublicKey);

impl From<PublicKey> for PublicKeyWrap {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

impl<'a> From<&'a PublicKey> for &'a PublicKeyWrap {
    fn from(pk: &PublicKey) -> Self {
        // unsafe { core::mem::transmute(pk) }
        let ptr: *const PublicKey = pk;
        unsafe { &*(ptr as *const PublicKeyWrap) }
    }
}

impl<'a> From<&'a mut PublicKey> for &'a mut PublicKeyWrap {
    fn from(pk: &mut PublicKey) -> Self {
        // unsafe { core::mem::transmute(pk) }
        let ptr: *mut PublicKey = pk;
        unsafe { &mut *(ptr as *mut PublicKeyWrap) }
    }
}

pub type Pks = HashSet<PublicKeyWrap>;
pub type IPk<'a> = &'a PublicKey;

pub fn filter_ke_pks<'a>(allowed_pks: &'a Pks, target_pks: &'a [PublicKey]) -> Vec<IPk<'a>> {
    target_pks
        .iter()
        .filter_map(|pk| allowed_pks.get(pk.into()).map(|pk| &pk.0))
        .collect::<Vec<IPk<'a>>>()
}

#[cfg(test)]
mod tests {
    struct FixedRng(Vec<u8>);
    impl rand::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            7
        }
        fn next_u64(&mut self) -> u64 {
            13
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0[..dest.len()]);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            dest.copy_from_slice(&self.0[..dest.len()]);
            Ok(())
        }
    }
    impl rand::CryptoRng for FixedRng {}

    fn test_25519<R>(rng: &mut R)
    where
        R: rand::CryptoRng + rand::RngCore,
    {
        let ed_kp = super::ed25519::Keypair::generate(rng);
        let x_kp = super::keypair_from_ed25519(&ed_kp);
        let x_pk2 = super::public_from_ed25519(&ed_kp.public);
        assert!(x_kp.1.as_bytes() == x_pk2.as_bytes());
    }

    #[test]
    fn test_25519_fixed() {
        let mut rng = FixedRng(vec![7_u8; 64]);
        test_25519(&mut rng);
        rng = FixedRng(vec![11_u8; 64]);
        test_25519(&mut rng);
    }

    #[test]
    fn test_25519_thread_rng() {
        test_25519(&mut rand::thread_rng());
    }
}
