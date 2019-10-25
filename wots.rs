use crate::trits::*;
use crate::spongos::*;
use crate::prng::*;

/// Size of a WOTS public key.
pub const PK_SIZE: usize = 243;
pub const PUBLIC_KEY_SIZE: usize = PK_SIZE;

/// Size of a WOTS private key part.
const SK_PART_SIZE: usize = 162;
const PRIVATE_KEY_PART_SIZE: usize = SK_PART_SIZE;

/// Number of parts in a WOTS private key.
const SK_PART_COUNT: usize = 81;
const PRIVATE_KEY_PART_COUNT: usize = SK_PART_COUNT;

/// Size of a WOTS private key.
pub const SK_SIZE: usize = SK_PART_SIZE * SK_PART_COUNT;
pub const PRIVATE_KEY_SIZE: usize = SK_SIZE;

/// Size of a WOTS signed hash.
pub const HASH_SIZE: usize = 234;

/// Size of a WOTS signature.
pub const SIG_SIZE: usize = PRIVATE_KEY_SIZE;
pub const SIGNATURE_SIZE: usize = SIG_SIZE;

/// h := hash_data^n(h)
fn rehash_data<TW>(n: usize, h: TritMutSlice<TW>) where TW: TritWord + Copy {
    for _ in 0..n {
        hash_data(h.as_const(), h);
    }
}

/// Generate WOTS secret private key with prng using a unique nonce.
fn gen_sk<TW>(prng: &PRNG<TW>, nonces: &[TritConstSlice<TW>], sk: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(sk.size() == PRIVATE_KEY_SIZE);
    prng.gens(nonces, sk);
}

/// Generate WOTS signature.
fn sign<TW>(mut sk: TritConstSlice<TW>, mut hash: TritConstSlice<TW>, mut sig: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(sk.size() == PRIVATE_KEY_SIZE);
    assert!(hash.size() == HASH_SIZE);
    assert!(sig.size() == SIGNATURE_SIZE);
    let mut t: Trint9 = 0;
    let mut sig_part = Trits::<TW>::zero(PRIVATE_KEY_PART_SIZE);

    for _ in 0..PRIVATE_KEY_PART_COUNT - 3 {
        let h = hash.get3();
        hash = hash.drop(3);
        t += h as Trint9;

        sk.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.mut_slice());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data((13 + h) as usize, sig_part.mut_slice());

        sig_part.slice().copy(sig.take(PRIVATE_KEY_PART_SIZE));
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);
    }

    t = -t;
    for _ in 0..3 {
        let (h, q) = mods3(t as i32);
        t = q as Trint9;

        sk.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.mut_slice());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data((13 + h) as usize, sig_part.mut_slice());

        sig_part.slice().copy(sig.take(PRIVATE_KEY_PART_SIZE));
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);
    }
}

/// Generate WOTS public key from secret key.
fn calc_pk<TW>(mut sk: TritConstSlice<TW>, pk: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(sk.size() == PRIVATE_KEY_SIZE);
    assert!(pk.size() == PUBLIC_KEY_SIZE);

    let mut sk_part = Trits::<TW>::zero(PRIVATE_KEY_PART_SIZE);
    let mut s = Spongos::<TW>::init();
    for _ in 0..PRIVATE_KEY_PART_COUNT {
        sk.take(PRIVATE_KEY_PART_SIZE).copy(sk_part.mut_slice());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data(26, sk_part.mut_slice());
        s.absorb(sk_part.slice());
    }
    s.commit();
    s.squeeze(pk);
}

/// Recover WOTS signer's public key from signature.
pub fn recover<TW>(mut hash: TritConstSlice<TW>, mut sig: TritConstSlice<TW>, pk: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(hash.size() == HASH_SIZE);
    assert!(sig.size() == SIGNATURE_SIZE);
    assert!(pk.size() == PUBLIC_KEY_SIZE);
    let mut t: Trint9 = 0;

    let mut sig_part = Trits::<TW>::zero(PRIVATE_KEY_PART_SIZE);
    let mut s = Spongos::<TW>::init();

    for _ in 0..PRIVATE_KEY_PART_COUNT - 3 {
        sig.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.mut_slice());
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);

        let h = hash.get3();
        hash = hash.drop(3);

        rehash_data((13 - h) as usize, sig_part.mut_slice());
        s.absorb(sig_part.slice());
        t += h as Trint9;
    }

    t = -t;
    for _ in 0..3 {
        sig.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.mut_slice());
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);

        let (h, q) = mods3(t as i32);
        t = q as Trint9;

        rehash_data((13 - h) as usize, sig_part.mut_slice());
        s.absorb(sig_part.slice());
    }

    s.commit();
    s.squeeze(pk);
}

pub struct PrivateKey<TW> {
    /// Private key of size `PRIVATE_KEY_SIZE` trits
    sk: Trits<TW>,
}

pub struct PublicKey<TW> {
    /// Public key of size `PUBLIC_KEY_SIZE` trits
    pk: Trits<TW>,
}

impl<TW> PrivateKey<TW> where TW: TritWord + Copy {
    /// Generate WOTS secret private key object.
    pub fn gen(prng: &PRNG<TW>, nonces: &[TritConstSlice<TW>]) -> Self {
        let mut sk = Self {
            sk: Trits::<TW>::zero(PRIVATE_KEY_SIZE),
        };
        gen_sk(prng, nonces, sk.sk.mut_slice());
        sk
    }
    /// Calculate WOTS public key trits.
    pub fn calc_pk(&self, pk: TritMutSlice<TW>) {
        calc_pk(self.sk.slice(), pk);
    }
    /// Generate WOTS signature.
    pub fn sign(&self, hash: TritConstSlice<TW>, sig: TritMutSlice<TW>) {
        sign(self.sk.slice(), hash, sig);
    }
}

impl<TW> PublicKey<TW> where TW: TritWord + Copy {
    /// Generate WOTS public key object.
    pub fn gen(sk: &PrivateKey<TW>) -> Self {
        let mut pk = Self {
            pk: Trits::<TW>::zero(PUBLIC_KEY_SIZE),
        };
        sk.calc_pk(pk.pk.mut_slice());
        pk
    }
    /// Verify WOTS signature.
    pub fn verify(&self, hash: TritConstSlice<TW>, sig: TritConstSlice<TW>) -> bool {
        let mut pk = Trits::<TW>::zero(PUBLIC_KEY_SIZE);
        recover(hash, sig, pk.mut_slice());
        self.pk == pk
    }
}

#[cfg(test)]
mod test_wots {
    use super::*;

    #[test]
    fn test_wots() {
        let k = Trits::<Trit>::zero(MAM_PRNG_SECRET_KEY_SIZE);
        let prng = PRNG::<Trit>::init(k.slice());
        let n = Trits::<Trit>::zero(33);
        let sk = PrivateKey::<Trit>::gen(&prng, &[n.slice()]);
        let pk = PublicKey::<Trit>::gen(&sk);

        let x = Trits::<Trit>::zero(123);
        let mut h = Trits::<Trit>::zero(HASH_SIZE);
        let mut s = Trits::<Trit>::zero(SIGNATURE_SIZE);

        hash_data(x.slice(), h.mut_slice());
        sk.sign(h.slice(), s.mut_slice());
        let r = pk.verify(h.slice(), s.slice());
        assert!(r, "WOTS verify failed");
        //TODO: modify h, s, pk
    }
}
