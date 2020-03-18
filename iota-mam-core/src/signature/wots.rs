use crate::prng::PRNGT;
use crate::sponge::spongos::{hash_data, SpongosT, prp::PRP};
use crate::tbits::{trinary::{util::mods3, Trint9}, TbitSliceT, TbitSliceMutT, TbitsT, SpongosTbitWord};

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
pub const SIG_SIZE: usize = SK_SIZE;
pub const SIGNATURE_SIZE: usize = SIG_SIZE;

/// h := hash_data^n(h)
/*
fn rehash_data<TW>(n: usize, h: TbitSliceMutT<TW>) {
    for _ in 0..n {
        hash_data(h.as_const(), h);
    }
}
 */

/// Generate WOTS secret private key with prng using a unique nonce.
fn gen_sk<TW, G>(prng: &PRNGT<TW, G>, nonces: &[TbitSliceT<TW>], sk: TbitSliceMutT<TW>)
where
    TW: SpongosTbitWord,
    G: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(SK_SIZE, sk.size());
    prng.gens(nonces, sk);
}

/*
/// Generate WOTS signature.
fn sign(mut sk: TritSlice, mut hash: TritSlice, mut sig: TritSliceMut) {
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(HASH_SIZE, hash.size());
    debug_assert_eq!(SIG_SIZE, sig.size());
    let mut t: Trint9 = Trint9(0);
    let mut sig_part = Trits::zero(PRIVATE_KEY_PART_SIZE);

    for _ in 0..PRIVATE_KEY_PART_COUNT - 3 {
        let h = hash.get3();
        hash = hash.drop(3);
        t.0 += h.0 as i16;

        sk.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.slice_mut());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data((13 + h.0) as usize, sig_part.slice_mut());

        sig_part.slice().copy(sig.take(PRIVATE_KEY_PART_SIZE));
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);
    }

    t.0 = -t.0;
    for _ in 0..3 {
        let (h, q) = mods3(t.0 as i32);
        t.0 = q as i16;

        sk.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.slice_mut());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data((13 + h.0) as usize, sig_part.slice_mut());

        sig_part.slice().copy(sig.take(PRIVATE_KEY_PART_SIZE));
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);
    }
}

/// Generate WOTS public key from secret key.
fn calc_pk(mut sk: TritSlice, pk: TritSliceMut) {
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(PK_SIZE, pk.size());

    let mut sk_part = Trits::zero(PRIVATE_KEY_PART_SIZE);
    let mut s = Spongos::init();
    for _ in 0..PRIVATE_KEY_PART_COUNT {
        sk.take(PRIVATE_KEY_PART_SIZE).copy(sk_part.slice_mut());
        sk = sk.drop(PRIVATE_KEY_PART_SIZE);
        rehash_data(26, sk_part.slice_mut());
        s.absorb(sk_part.slice());
    }
    s.commit();
    s.squeeze(pk);
}

/// Recover WOTS signer's public key from signature.
pub fn recover(mut hash: TritSlice, mut sig: TritSlice, pk: TritSliceMut) {
    debug_assert_eq!(HASH_SIZE, hash.size());
    debug_assert_eq!(SIG_SIZE, sig.size());
    debug_assert_eq!(PK_SIZE, pk.size());
    let mut t: Trint9 = Trint9(0);

    let mut sig_part = Trits::zero(PRIVATE_KEY_PART_SIZE);
    let mut s = Spongos::init();

    for _ in 0..PRIVATE_KEY_PART_COUNT - 3 {
        sig.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.slice_mut());
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);

        let h = hash.get3();
        hash = hash.drop(3);

        rehash_data((13 - h.0) as usize, sig_part.slice_mut());
        s.absorb(sig_part.slice());
        t.0 += h.0 as i16;
    }

    t.0 = -t.0;
    for _ in 0..3 {
        sig.take(PRIVATE_KEY_PART_SIZE).copy(sig_part.slice_mut());
        sig = sig.drop(PRIVATE_KEY_PART_SIZE);

        let (h, q) = mods3(t.0 as i32);
        t = Trint9(q as i16);

        rehash_data((13 - h.0) as usize, sig_part.slice_mut());
        s.absorb(sig_part.slice());
    }

    s.commit();
    s.squeeze(pk);
}

pub struct PrivateKey {
    /// Private key of size `PRIVATE_KEY_SIZE` trits
    sk: Trits,
}

pub struct PublicKey {
    /// Public key of size `PUBLIC_KEY_SIZE` trits
    pk: Trits,
}

impl PrivateKey {
    /// Generate WOTS secret private key object.
    pub fn gen(prng: &PRNG, nonces: &[TritSlice]) -> Self {
        let mut sk = Self {
            sk: Trits::zero(PRIVATE_KEY_SIZE),
        };
        gen_sk(prng, nonces, sk.sk.slice_mut());
        sk
    }
    /// Calculate WOTS public key trits.
    pub fn calc_pk(&self, pk: TritSliceMut) {
        calc_pk(self.sk.slice(), pk);
    }
    /// Generate WOTS signature.
    pub fn sign(&self, hash: TritSlice, sig: TritSliceMut) {
        sign(self.sk.slice(), hash, sig);
    }
}

impl PublicKey {
    /// Generate WOTS public key object.
    pub fn gen(sk: &PrivateKey) -> Self {
        let mut pk = Self {
            pk: Trits::zero(PUBLIC_KEY_SIZE),
        };
        sk.calc_pk(pk.pk.slice_mut());
        pk
    }
    /// Verify WOTS signature.
    pub fn verify(&self, hash: TritSlice, sig: TritSlice) -> bool {
        let mut pk = Trits::zero(PUBLIC_KEY_SIZE);
        recover(hash, sig, pk.slice_mut());
        self.pk == pk
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prng::{self, PRNG};

    #[test]
    fn sign_verify() {
        let k = Trits::zero(prng::KEY_SIZE);
        let prng = PRNG::init(k.slice());
        let n = Trits::zero(33);
        let sk = PrivateKey::gen(&prng, &[n.slice()]);
        let pk = PublicKey::gen(&sk);

        let x = Trits::zero(123);
        let mut h = Trits::zero(HASH_SIZE);
        let mut s = Trits::zero(SIGNATURE_SIZE);

        hash_data(x.slice(), h.slice_mut());
        sk.sign(h.slice(), s.slice_mut());
        let r = pk.verify(h.slice(), s.slice());
        assert!(r, "WOTS verify failed");
        //TODO: modify h, s, pk
    }
}
 */
