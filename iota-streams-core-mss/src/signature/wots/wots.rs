use iota_streams_core::{
    hash::Hash,
    prng::Prng,
    sponge::prp::PRP,
    tbits::{
        word::{BasicTbitWord, IntTbitWord, SpongosTbitWord},
        TbitSlice, TbitSliceMut, Tbits,
    },
};

pub trait Parameters<TW> {
    /// Type of hash function used for iterative private key part rehashing.
    type H: Hash<TW> + Default;
    /// Size of a WOTS private key part.
    const PRIVATE_KEY_PART_SIZE: usize = Self::H::HASH_SIZE; // 162

    /// Size of a WOTS signed hash.
    const HASH_SIZE: usize = Self::HASH_PART_COUNT * Self::HASH_PART_SIZE; // HASH_PART_COUNT * 3 = 234
    const HASH_PART_SIZE: usize; // 3
    const HASH_PART_MODULUS: usize; // (2|3)^HASH_PART_SIZE = 27
    const HASH_PART_COUNT: usize; // 78
    const CHECKSUM_PART_COUNT: usize; // 3

    /// Number of parts in a WOTS private key.
    const PRIVATE_KEY_PART_COUNT: usize = Self::HASH_PART_COUNT + Self::CHECKSUM_PART_COUNT; // 81

    /// Size of a WOTS private key.
    const PRIVATE_KEY_SIZE: usize = Self::PRIVATE_KEY_PART_SIZE * Self::PRIVATE_KEY_PART_COUNT;

    /// Size of a WOTS signature.
    const SIGNATURE_SIZE: usize = Self::PRIVATE_KEY_SIZE;

    /// Type of hash function used to generate public key;
    type J: Hash<TW> + Default;

    /// Size of a WOTS public key.
    const PUBLIC_KEY_SIZE: usize = Self::J::HASH_SIZE; // 243
}

/// h := hash_data^n(h)
/*
fn rehash_data<TW>(n: usize, h: TbitSliceMut<TW>) {
    for _ in 0..n {
        hash_data(h.as_const(), h);
    }
}
 */

/// Generate WOTS secret private key with prng using a unique nonce.
fn gen_sk<TW, G>(prng: &Prng<TW, G>, nonces: &[TbitSlice<TW>], sk: TbitSliceMut<TW>)
where
    TW: SpongosTbitWord,
    G: PRP<TW> + Default,
{
    //debug_assert_eq!(SK_SIZE, sk.size());
    prng.gens(nonces, sk);
}

fn rehash<TW, H>(count: usize, value: &mut Tbits<TW>)
where
    TW: BasicTbitWord,
    H: Hash<TW>,
{
    for _ in 0..count {
        H::rehash_tbits(value);
    }
}

/// Generate WOTS signature.
fn sign<TW, P>(mut sk: TbitSlice<TW>, mut hash: TbitSlice<TW>, mut sig: TbitSliceMut<TW>)
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    debug_assert_eq!(P::PRIVATE_KEY_SIZE, sk.size());
    debug_assert_eq!(P::HASH_SIZE, hash.size());
    debug_assert_eq!(P::SIGNATURE_SIZE, sig.size());
    let mut t = 0_usize;
    let mut sig_part = Tbits::<TW>::zero(P::PRIVATE_KEY_PART_SIZE);

    for _ in 0..P::HASH_PART_COUNT {
        let r = hash.advance(P::HASH_PART_SIZE).get_usize();
        t += r;

        sk.advance(P::PRIVATE_KEY_PART_SIZE)
            .copy(&sig_part.slice_mut());
        rehash::<TW, P::H>(P::HASH_PART_MODULUS - r, &mut sig_part);

        sig_part
            .slice()
            .copy(&sig.advance(P::PRIVATE_KEY_PART_SIZE));
    }

    for _ in 0..P::CHECKSUM_PART_COUNT {
        let r = t % P::HASH_PART_MODULUS;
        t = t / P::HASH_PART_MODULUS;

        sk.advance(P::PRIVATE_KEY_PART_SIZE)
            .copy(&sig_part.slice_mut());
        rehash::<TW, P::H>(r, &mut sig_part);

        sig_part
            .slice()
            .copy(&sig.advance(P::PRIVATE_KEY_PART_SIZE));
    }
}

/// Generate WOTS public key from secret key.
fn calc_pk<TW, P>(mut sk: TbitSlice<TW>, mut pk: TbitSliceMut<TW>)
where
    TW: BasicTbitWord,
    P: Parameters<TW>,
{
    debug_assert_eq!(P::PRIVATE_KEY_SIZE, sk.size());
    debug_assert_eq!(P::PUBLIC_KEY_SIZE, pk.size());

    let mut sk_part = Tbits::<TW>::zero(P::PRIVATE_KEY_PART_SIZE);
    let mut s = P::J::init();
    for _ in 0..P::PRIVATE_KEY_PART_COUNT {
        sk.advance(P::PRIVATE_KEY_PART_SIZE)
            .copy(&sk_part.slice_mut());
        rehash::<TW, P::H>(P::HASH_PART_MODULUS, &mut sk_part);
        s.update(sk_part.slice());
    }
    s.done(&mut pk);
}

/// Recover WOTS signer's public key from signature.
pub fn recover<TW, P>(mut hash: TbitSlice<TW>, mut sig: TbitSlice<TW>, mut pk: TbitSliceMut<TW>)
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    debug_assert_eq!(P::HASH_SIZE, hash.size());
    debug_assert_eq!(P::SIGNATURE_SIZE, sig.size());
    debug_assert_eq!(P::PUBLIC_KEY_SIZE, pk.size());
    let mut t = 0_usize;

    let mut sig_part = Tbits::<TW>::zero(P::PRIVATE_KEY_PART_SIZE);
    let mut s = P::J::init();

    for _ in 0..P::HASH_PART_COUNT {
        let r = hash.advance(P::HASH_PART_SIZE).get_usize();

        sig.advance(P::PRIVATE_KEY_PART_SIZE)
            .copy(&sig_part.slice_mut());
        rehash::<TW, P::H>(r, &mut sig_part);
        s.update(sig_part.slice());
        t += r;
    }

    //t = -t;
    for _ in 0..P::CHECKSUM_PART_COUNT {
        let r = t % P::HASH_PART_MODULUS;
        t = t / P::HASH_PART_MODULUS;

        sig.advance(P::PRIVATE_KEY_PART_SIZE)
            .copy(&sig_part.slice_mut());
        rehash::<TW, P::H>(P::HASH_PART_MODULUS - r, &mut sig_part);
        s.update(sig_part.slice());
    }

    s.done(&mut pk);
}

pub struct PrivateKey<TW, P> {
    /// Private key of size `PRIVATE_KEY_SIZE` tbits
    sk: Tbits<TW>,
    _phantom: std::marker::PhantomData<P>,
}

pub struct PublicKey<TW, P> {
    /// Public key of size `PUBLIC_KEY_SIZE` tbits
    pk: Tbits<TW>,
    _phantom: std::marker::PhantomData<P>,
}

impl<TW, P> PrivateKey<TW, P>
where
    TW: SpongosTbitWord,
    P: Parameters<TW>,
{
    /// Generate WOTS secret private key object.
    pub fn gen<G>(prng: &Prng<TW, G>, nonces: &[TbitSlice<TW>]) -> Self
    where
        G: PRP<TW> + Default,
    {
        let mut sk = Self {
            sk: Tbits::<TW>::zero(P::PRIVATE_KEY_SIZE),
            _phantom: std::marker::PhantomData,
        };
        gen_sk(prng, nonces, sk.sk.slice_mut());
        sk
    }
}

impl<TW, P> PrivateKey<TW, P>
where
    TW: BasicTbitWord,
    P: Parameters<TW>,
{
    /// Calculate WOTS public key tbits.
    pub fn calc_pk(&self, pk: TbitSliceMut<TW>) {
        calc_pk::<TW, P>(self.sk.slice(), pk);
    }
}

impl<TW, P> PrivateKey<TW, P>
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    /// Generate WOTS signature.
    pub fn sign(&self, hash: TbitSlice<TW>, sig: TbitSliceMut<TW>) {
        sign::<TW, P>(self.sk.slice(), hash, sig);
    }

    pub fn sign_tbits(&self, hash: &Tbits<TW>) -> Tbits<TW> {
        let mut sig = Tbits::<TW>::zero(P::SIGNATURE_SIZE);
        self.sign(hash.slice(), sig.slice_mut());
        sig
    }
}

impl<TW, P> PublicKey<TW, P>
where
    TW: BasicTbitWord,
    P: Parameters<TW>,
{
    /// Generate WOTS public key object.
    pub fn gen(sk: &PrivateKey<TW, P>) -> Self {
        let mut pk = Self {
            pk: Tbits::<TW>::zero(P::PUBLIC_KEY_SIZE),
            _phantom: std::marker::PhantomData,
        };
        sk.calc_pk(pk.pk.slice_mut());
        pk
    }
}

impl<TW, P> PublicKey<TW, P>
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    /// Verify WOTS signature.
    pub fn verify(&self, hash: TbitSlice<TW>, sig: TbitSlice<TW>) -> bool {
        let mut pk = Tbits::zero(P::PUBLIC_KEY_SIZE);
        recover::<TW, P>(hash, sig, pk.slice_mut());
        self.pk == pk
    }

    pub fn verify_tbits(&self, hash: &Tbits<TW>, sig: &Tbits<TW>) -> bool {
        self.verify(hash.slice(), sig.slice())
    }
}
