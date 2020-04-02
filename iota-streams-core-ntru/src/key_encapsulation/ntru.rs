use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::hash;

use iota_streams_core::prng::Prng;
use iota_streams_core::sponge::{prp::PRP, spongos::Spongos};
use iota_streams_core::tbits::{
    trinary::TritWord,
    word::{BasicTbitWord, SpongosTbitWord},
    TbitSlice, TbitSliceMut, Tbits,
};

use super::poly::*;

/// NTRU public key - 3g(x)/(1+3f(x)) - size.
pub const PK_SIZE: usize = 9216;
pub const PUBLIC_KEY_SIZE: usize = PK_SIZE;

/// NTRU public key id size.
pub const PKID_SIZE: usize = 81;

/// NTRU private key - f(x) - size.
pub const SK_SIZE: usize = 1024;
pub const PRIVATE_KEY_SIZE: usize = SK_SIZE;

///// NTRU session symmetric key size.
//pub const KEY_SIZE: usize = 243;//crate::spongos::KEY_SIZE;

/// NTRU encrypted key size.
pub const EKEY_SIZE: usize = 9216;

/// Check "small" polys `f` and `g` for being suitable to gen NTRU keypair.
/// Output:
///   `f_out = NTT(1+3f)` -- private key NTT representation;
///   `h_out = NTT(3g/(1+3f))` -- public key NTT representation.
fn gen_step(f: &mut Poly, g: &mut Poly, h: &mut Poly) -> bool {
    // f := NTT(1+3f)
    f.small_mul3();
    f.small3_add1();
    f.ntt();

    // g := NTT(3g)
    g.small_mul3();
    g.ntt();

    if f.has_inv() && g.has_inv() {
        // h := NTT(3g/(1+3f))
        *h = *f;
        h.inv();
        h.conv(&g);

        true
    } else {
        false
    }
}

/// Try generate NTRU key pair using `prng` and `nonce`.
/// In case of success `sk` is private key, `pk` is public key, `f` is `NTT(1+3sk)`, `h` is `NTT(pk)`.
fn gen_with_prng<TW, G>(
    prng: &Prng<TW, G>,
    nonce: TbitSlice<TW>,
    f: &mut Poly,
    mut sk: TbitSliceMut<TW>,
    h: &mut Poly,
    mut pk: TbitSliceMut<TW>,
) -> bool
where
    TW: TritWord + SpongosTbitWord,
    G: PRP<TW> + Default,
{
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(PK_SIZE, pk.size());

    let mut i = Tbits::zero(81);
    let mut r = Tbits::zero(2 * SK_SIZE);
    let mut g = Poly::new();

    loop {
        {
            let nonces = [nonce, i.slice()];
            prng.gens(&nonces, r.slice_mut());
        }
        let (f_slice, g_slice) = r.slice().split_at(SK_SIZE);
        f.small_from_trits(f_slice);
        g.small_from_trits(g_slice);

        if gen_step(f, &mut g, h) {
            //h.intt();
            g = *h;
            g.intt();
            g.to_trits(&mut pk);
            r.slice().take(SK_SIZE).copy(&mut sk);
            break;
        }

        if !i.slice_mut().inc() {
            return false;
        }
    }
    true
}

/*
fn encrypt_with_fo_transform<TW, FO>(h: &Poly, r: TbitSliceMut<TW>, y: TbitSliceMut<TW>, fo: FO)
    where
    TW: TritWord,
    FO: FnOnce(TbitSlice<TW>, TbitSliceMut<TW>) -> (),
{
    debug_assert_eq!(SK_SIZE, r.size());
    debug_assert_eq!(EKEY_SIZE, y.size());

    unsafe {
        let mut t = Poly::new();

        // t(x) := r(x)*h(x)
        t.small_from_trits(r.as_const());
        t.ntt();
        t.conv(&h);
        t.intt();

        // h(x) = AE(r*h;k)
        t.to_trits2(y.clone());
        fo(y.as_const(), r.clone());

        // y = r*h + AE(r*h;k)
        t.add_small(r.as_const());
        t.to_trits2(y);
    }
}

/// Encrypt secret key `key` with NTRU public key `h`, randomness `r` with spongos instance `s` and put the encrypted key into `encapsulated_key`.
fn encrypt_with_randomness<TW, F>(s: &mut Spongos<TW, F>, h: &Poly, r: TbitSliceMut<TW>, key: TbitSlice<TW>, encapsulated_key: TbitSliceMut<TW>)
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
{
    //debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert!(key.size() < EKEY_SIZE);
    let fo = |y: TbitSlice<TW>, r: TbitSliceMut<TW>| {
        //s.init();
        s.absorb(y);
        s.commit();
        let (ekey, tag) = r.split_at(key.size());
        s.encrypt2(key, ekey);
        s.squeeze2(tag);
    };
    encrypt_with_fo_transform(h, r, encapsulated_key, fo);
}
 */

fn encrypt_with_fo_transform_mut<TW, FO>(h: &Poly, y: TbitSliceMut<TW>, fo: FO)
where
    TW: TritWord,
    FO: FnOnce(TbitSliceMut<TW>) -> (),
{
    debug_assert_eq!(EKEY_SIZE, y.size());

    // h(x) = NTT(3g/(1+3f))

    let mut rh_poly = Poly::new();

    // rh_poly(x) := r(x)*h(x)
    unsafe {
        // Randomness is in the first `SK_SIZE` trits of `y`.
        let r = y.clone().take(SK_SIZE).as_const();
        rh_poly.small_from_trits(r);
        rh_poly.ntt();
        rh_poly.conv(&h);
        rh_poly.intt();
    }

    // h(x) = fo(r*h) = AE(r*h; key)
    unsafe {
        let rh = y.clone();
        rh_poly.to_trits2(rh.clone());
        // Encrypt `key` with r*h as key encryption key and nonce.
        fo(rh);
    }

    // y = r*h + AE(r*h; key)
    unsafe {
        let encrypted_key = y.clone().take(SK_SIZE).as_const();
        rh_poly.add_small(encrypted_key);
    }
    rh_poly.to_trits2(y);
}

/// Encrypt secret key `k` with NTRU public key `h`, randomness `r` with spongos instance `s` and put the encrypted key into `y`.
fn encrypt_with_randomness_mut<TW, F>(
    s: &mut Spongos<TW, F>,
    h: &Poly,
    key: TbitSlice<TW>,
    encapsulated_key: TbitSliceMut<TW>,
) where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
{
    //debug_assert_eq!(KEY_SIZE, key.size());
    debug_assert!(key.size() < EKEY_SIZE);
    let fo = |y: TbitSliceMut<TW>| {
        unsafe {
            //s.init();
            let rh = y.as_const();
            s.absorb(rh);
            s.commit();
            let (ekey, tag) = y.split_at(key.size());
            s.encrypt2(key, ekey);
            s.squeeze2(tag);
        }
    };
    encrypt_with_fo_transform_mut(h, encapsulated_key, fo);
}

/// Encrypt secret key `key` with NTRU public key `pk`, public polynomial `h = NTT(pk)` using `prng`, nonce `nonce` and spongos instance `s`. Put encrypted key into `encapsulated_key`.
pub fn encrypt_with_pk<TW, F, G>(
    s: &mut Spongos<TW, F>,
    prng: &Prng<TW, G>,
    pk: TbitSlice<TW>,
    h: &Poly,
    nonce: TbitSlice<TW>,
    key: TbitSlice<TW>,
    encapsulated_key: TbitSliceMut<TW>,
) where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
    G: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(PK_SIZE, pk.size());
    //debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert!(key.size() < EKEY_SIZE);
    debug_assert_eq!(EKEY_SIZE, encapsulated_key.size());

    /*
    let mut rnd = Tbits::<TW>::zero(SK_SIZE);
    {
        // Use pk, key, nonce as nonces.
        let nonces = [pk, key, nonce];
        prng.gens(&nonces, rnd.slice_mut());
    }
    encrypt_with_randomness(s, h, rnd.slice_mut(), key, encapsulated_key);
     */

    // Reuse `encapsulated_key` slice for randomness.
    unsafe {
        // Use pk, key, nonce as nonces.
        let nonces = [pk, key, nonce];
        // Put randomness into the first `SK_SIZE` trits of the output `encapsulated_key`.
        let rnd = encapsulated_key.clone().take(SK_SIZE);
        prng.gens(&nonces, rnd);
    }
    encrypt_with_randomness_mut(s, h, key, encapsulated_key);
}

/// Create a public key polynomial `h = NTT(pk)` from tbits `pk` and check it (for invertibility).
fn pk_from_trits<TW>(pk: TbitSlice<TW>) -> Option<Poly>
where
    TW: TritWord,
{
    let mut h = Poly::new();
    if h.from_trits(pk) {
        h.ntt();
        if h.has_inv() {
            Some(h)
        } else {
            None
        }
    } else {
        None
    }
}

fn decrypt_with_fo_transform<TW, FO>(f: &Poly, y: TbitSlice<TW>, fo: FO) -> bool
where
    TW: TritWord + SpongosTbitWord,
    FO: FnOnce(TbitSlice<TW>, TbitSlice<TW>) -> bool,
{
    debug_assert_eq!(EKEY_SIZE, y.size());

    // f(x) = NTT(1+3f)
    // h(x) = NTT(3g/(1+3f))

    let mut rh_poly = Poly::new();
    // rh(x) := Y = r*h + AE(r*h; key)
    if !rh_poly.from_trits(y) {
        return false;
    }

    // r(x) := rh(x)*(1+3f(x)) (mods 3) =
    // = ( (r*3g/(1+3f) + AE(rh; key))*(1+3f) ) (mods 3) =
    // = ( 3(r*g + AE(rh; key)*f) + AE(rh; key) ) (mods 3) =
    // = AE(rh; key)
    let mut r = rh_poly;
    r.ntt();
    r.conv(&f);
    r.intt();
    let mut kt = Tbits::zero(SK_SIZE);
    r.round_to_trits2(kt.slice_mut());

    // t(x) := Y - r(x)
    rh_poly.sub_small(kt.slice());
    let mut rh = Tbits::zero(EKEY_SIZE);
    rh_poly.to_trits2(rh.slice_mut());

    // K = AD(r*h; kt)
    fo(rh.slice(), kt.slice())
}

/// Try to decrypt encapsulated key `y` with private polynomial `f` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
fn decrypt_with_randomness<TW, F>(
    s: &mut Spongos<TW, F>,
    f: &Poly,
    y: TbitSlice<TW>,
    k: TbitSliceMut<TW>,
) -> bool
where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
{
    //debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert!(k.size() < EKEY_SIZE);
    let fo = |rh: TbitSlice<TW>, kt: TbitSlice<TW>| -> bool {
        //spongos_init(s);
        s.absorb(rh);
        s.commit();
        let key_size = k.size();
        s.decrypt2(kt.take(key_size), k);
        s.squeeze_eq(kt.drop(key_size))
    };
    decrypt_with_fo_transform(f, y, fo)
}

/// Try to decrypt encapsulated key `y` with private key `sk` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
pub fn decrypt_with_sk<TW, F>(
    s: &mut Spongos<TW, F>,
    sk: TbitSlice<TW>,
    y: TbitSlice<TW>,
    k: TbitSliceMut<TW>,
) -> bool
where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
{
    debug_assert_eq!(SK_SIZE, sk.size());
    //debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert!(k.size() < EKEY_SIZE);
    debug_assert_eq!(EKEY_SIZE, y.size());

    let mut f = Poly::new();
    f.small_from_trits(sk);

    // f := NTT(1+3f)
    f.small_mul3();
    f.small3_add1();
    f.ntt();

    decrypt_with_randomness(s, &f, y, k)
}

/// Private key object, contains secret trits `sk` and polynomial `f = NTT(1+3sk)`
/// which serves as a precomputed value during decryption.
#[derive(Clone)]
pub struct PrivateKey<TW, F> {
    sk: Tbits<TW>,
    f: Poly, // NTT(1+3f)
    _phantom: std::marker::PhantomData<F>,
}

/// Public key object, contains trinary representation `pk` of public polynomial
/// as well as it's NTT form in `h`.
#[derive(Clone)]
pub struct PublicKey<TW, F> {
    pk: Tbits<TW>,
    h: Poly, // NTT(3g/(1+3f))
    _phantom: std::marker::PhantomData<F>,
}

/// Default implementation for PublicKey. Note, this object is not valid and can't be
/// used for encapsulating keys. This instance exists in order to simplify deserialization
/// of public keys. Once public key trits have been deserialized the object must be `validate`d. If the `validate` method returns `false` then the object is invalid.
/// Otherwise it's valid and can be used for encapsulating secrets.
//TODO: Introduce PrePublicKey with Default implementation and `fn validate(self) -> Option<PublicKey>`.
impl<TW, F> Default for PublicKey<TW, F>
where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            pk: Tbits::zero(PK_SIZE),
            h: Poly::new(),
            _phantom: std::marker::PhantomData,
        }
    }
}

/*
impl<TW> fmt::Display for PublicKey<TW>
    where
    TW: TritWord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}
 */

impl<TW, F> fmt::Debug for PublicKey<TW, F>
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.pk)
    }
}

impl<TW, F> PartialEq for PublicKey<TW, F>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}
impl<TW, F> Eq for PublicKey<TW, F> where TW: BasicTbitWord {}

/// Same implementation as for Pkid.
/// The main property: `pk1 == pk2 => hash(pk1) == hash(pk2)` holds.
impl<TW, F> hash::Hash for PublicKey<TW, F>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.tbits().slice().take(PKID_SIZE)).hash(state);
    }
}

/// For types implementing `Borrow` the following statement must be true:
/// "x.borrow() == y.borrow() should give the same result as x == y".
/// For `PublicKey` this doesn't hold but with neglegible probability.
impl<TW, F> Borrow<Pkid<TW>> for PublicKey<TW, F> {
    fn borrow(&self) -> &Pkid<TW> {
        unsafe { std::mem::transmute(self.tbits()) }
    }
}

/// Thin wrapper around Tbits which contains either a full public key or the first `PKID_SIZE` of the public key.
pub struct Pkid<TW>(pub Tbits<TW>);

impl<TW> Pkid<TW> {
    pub fn tbits(&self) -> &Tbits<TW> {
        &self.0
    }
    pub fn tbits_mut(&mut self) -> &mut Tbits<TW> {
        &mut self.0
    }
}

impl<TW> AsRef<Tbits<TW>> for Pkid<TW> {
    fn as_ref(&self) -> &Tbits<TW> {
        &self.0
    }
}

impl<TW> AsRef<Pkid<TW>> for Tbits<TW> {
    fn as_ref(&self) -> &Pkid<TW> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<TW> PartialEq for Pkid<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.tbits().slice().take(PKID_SIZE) == other.tbits().slice().take(PKID_SIZE)
    }
}

impl<TW> Eq for Pkid<TW> where TW: BasicTbitWord {}

/// Hash of public key identifier (the first `PKID_SIZE` tbits of the public key).
/// This is implemented
/// `k1 == k2 -> hash(k1) == hash(k2)`
impl<TW> hash::Hash for Pkid<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.tbits().slice().take(PKID_SIZE)).hash(state);
    }
}

/// Generate NTRU keypair with `prng` and `nonce`.
pub fn gen_keypair<TW, F, G>(
    prng: &Prng<TW, G>,
    nonce: TbitSlice<TW>,
) -> (PrivateKey<TW, F>, PublicKey<TW, F>)
where
    TW: TritWord + SpongosTbitWord,
    G: PRP<TW> + Default,
{
    let mut sk = PrivateKey {
        sk: Tbits::zero(SK_SIZE),
        f: Poly::new(),
        _phantom: std::marker::PhantomData,
    };
    let mut pk = PublicKey {
        pk: Tbits::zero(PK_SIZE),
        h: Poly::new(),
        _phantom: std::marker::PhantomData,
    };

    let ok = gen_with_prng(
        &prng,
        nonce,
        &mut sk.f,
        sk.sk.slice_mut(),
        &mut pk.h,
        pk.pk.slice_mut(),
    );
    // Public key generation should generally succeed.
    assert!(ok);
    (sk, pk)
}

impl<TW, F> PrivateKey<TW, F>
where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW>,
{
    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using spongos instance `s`.
    pub fn decrypt_with_spongos(
        &self,
        s: &mut Spongos<TW, F>,
        y: TbitSlice<TW>,
        k: TbitSliceMut<TW>,
    ) -> bool {
        decrypt_with_sk(s, self.sk.slice(), y, k)
    }

    /*
    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using new spongos instance.
    pub fn decrypt_with_troika(&self, y: TbitSlice<TW>, k: TbitSliceMut<TW>) -> bool {
        let mut s = Spongos::<TW, Troika>::init();
        self.decrypt_with_spongos(&mut s, y, k)
    }
     */
}

impl<TW, F> PublicKey<TW, F> {
    /// Public polinomial tbits.
    pub fn tbits(&self) -> &Tbits<TW> {
        &self.pk
    }

    /// Public polinomial tbits, once public key has been modified it must be `validate`d.
    pub fn tbits_mut(&mut self) -> &mut Tbits<TW> {
        &mut self.pk
    }
}

impl<TW, F> PublicKey<TW, F>
where
    TW: BasicTbitWord,
{
    /// Returns the actual Pkid value trimmed to PKID_SIZE, not the fake borrowed one.
    pub fn get_pkid(&self) -> Pkid<TW> {
        Pkid(Tbits::from_slice(self.tbits().slice().take(PKID_SIZE)))
    }

    pub fn cmp_pkid(&self, pkid: &Pkid<TW>) -> bool {
        self.pk.size() == PK_SIZE
            && pkid.tbits().size() == PKID_SIZE
            && self.pk.slice().take(PKID_SIZE) == pkid.tbits().slice()
    }

    /// Return public polinomial tbits slice.
    pub fn slice(&self) -> TbitSlice<TW> {
        self.pk.slice()
    }

    /// Public key identifier -- the first `PKID_SIZE` tbits of the public key.
    pub fn id(&self) -> TbitSlice<TW> {
        self.pk.slice().take(PKID_SIZE)
    }
}

impl<TW, F> PublicKey<TW, F>
where
    TW: TritWord,
{
    /// Try to create `PublicKey` object from tbits `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_trits(pk: Tbits<TW>) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk.slice())?;
            Some(PublicKey {
                pk,
                h,
                _phantom: std::marker::PhantomData,
            })
        } else {
            None
        }
    }

    /// Try to create `PublicKey` object from slice `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_slice(pk: TbitSlice<TW>) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk)?;
            Some(PublicKey {
                pk: Tbits::from_slice(pk),
                h,
                _phantom: std::marker::PhantomData,
            })
        } else {
            None
        }
    }

    /// Precompute polynomial `h = NTT(pk)` and check for invertibility.
    pub fn validate(&mut self) -> bool {
        if let Some(h) = pk_from_trits(self.pk.slice()) {
            self.h = h;
            true
        } else {
            false
        }
    }
}

impl<TW, F> PublicKey<TW, F>
where
    TW: TritWord + SpongosTbitWord,
{
    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using spongos instance `s` and put "capsule" into `y`.
    pub fn encrypt_with_spongos<G>(
        &self,
        s: &mut Spongos<TW, F>,
        prng: &Prng<TW, G>,
        nonce: TbitSlice<TW>,
        k: TbitSlice<TW>,
        y: TbitSliceMut<TW>,
    ) where
        F: PRP<TW>,
        G: PRP<TW> + Clone + Default,
    {
        encrypt_with_pk(s, prng, self.pk.slice(), &self.h, nonce, k, y);
    }

    /*
    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using new spongos instance and put "capsule" into `y`.
    pub fn encrypt_with_troika<G>(&self, prng: &Prng<TW, G>, nonce: TbitSlice<TW>, k: TbitSlice<TW>, y: TbitSliceMut<TW>)
        where
        G: PRP<TW> + Clone + Default,
    {
        let mut s = Spongos::<TW, Troika>::init();
        self.encrypt_with_spongos(&mut s, prng, nonce, k, y);
    }
     */
}

/// Container for NTRU public keys.
pub type NtruPks<TW, F> = HashSet<PublicKey<TW, F>>;

/// Entry in a container, just a convenience type synonym.
pub type INtruPk<'a, TW, F> = &'a PublicKey<TW, F>;

/// Container (set) of NTRU public key identifiers.
pub type NtruPkids<TW> = Vec<Pkid<TW>>;

/// Select only NTRU public keys with given identifiers.
pub fn filter_ntru_pks<'a, TW, F>(
    ntru_pks: &'a NtruPks<TW, F>,
    ntru_pkids: &'_ NtruPkids<TW>,
) -> Vec<INtruPk<'a, TW, F>>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    ntru_pkids
        .iter()
        .filter_map(|pkid| ntru_pks.get(pkid))
        .collect::<Vec<INtruPk<'a, TW, F>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_streams_core::prng;
    use iota_streams_core::sponge::prp::troika::Troika;
    use iota_streams_core::tbits::{binary::Byte, trinary::Trit};
    use iota_streams_core_keccak::sponge::prp::keccak::{KeccakF1600B, KeccakF1600T};

    fn encrypt_decrypt_tbits<TW, F, G>()
    where
        TW: TritWord + SpongosTbitWord,
        F: PRP<TW> + Clone + Default,
        G: PRP<TW> + Clone + Default,
    {
        const KEY_SIZE: usize = 243;
        let prng_key = Tbits::<TW>::zero(prng::Prng::<TW, G>::KEY_SIZE);
        let prng = Prng::<TW, G>::init(prng_key);
        let nonce = Tbits::<TW>::zero(15);
        let k = Tbits::<TW>::zero(KEY_SIZE);
        let mut ek = Tbits::<TW>::zero(EKEY_SIZE);
        let mut dek = Tbits::<TW>::zero(KEY_SIZE);

        /*
        let mut sk = PrivateKey {
            sk: Tbits::zero(SK_SIZE),
            f: Poly::new(),
        };
        let mut pk = PublicKey {
            pk: Tbits::zero(PK_SIZE),
        };
        {
            let mut r = Tbits::zero(SK_SIZE);
            r.slice_mut().setTbit(1);
            sk.f.small_from_tbits(r.slice());
            let mut g = Poly::new();
            g.small_from_tbits(r.slice());
            g.small3_add1();
            g.small3_add1();
            let mut h = Poly::new();

            if gen_step(&mut sk.f, &mut g, &mut h) {
                h.to_tbits(pk.pk.slice_mut());
            } else {
                debug_assert!(false);
            }
        }
         */
        let (sk, pk) = gen_keypair(&prng, nonce.slice());

        {
            let mut s = Spongos::<TW, F>::init();
            pk.encrypt_with_spongos(&mut s, &prng, nonce.slice(), k.slice(), ek.slice_mut());
        }

        let ok = {
            let mut s = Spongos::<TW, F>::init();
            sk.decrypt_with_spongos(&mut s, ek.slice(), dek.slice_mut())
        };
        assert!(ok);

        assert!(k == dek);
    }

    #[test]
    fn encrypt_decrypt_troika_b1t1() {
        encrypt_decrypt_tbits::<Trit, Troika, Troika>();
    }
    #[test]
    fn encrypt_decrypt_troika_b1t1_x100() {
        for _ in 0..100 {
            encrypt_decrypt_tbits::<Trit, Troika, Troika>();
        }
    }

    /*
    #[test]
    fn encrypt_decrypt_keccak_b1b8() {
        encrypt_decrypt_tbits::<Byte, KeccakF1600B, KeccakF1600B>();
    }
     */

    #[test]
    fn encrypt_decrypt_keccak_b1t1() {
        encrypt_decrypt_tbits::<Trit, KeccakF1600T, KeccakF1600T>();
    }
    #[test]
    fn encrypt_decrypt_keccak_b1t1_x100() {
        for _ in 0..100 {
            encrypt_decrypt_tbits::<Trit, KeccakF1600T, KeccakF1600T>();
        }
    }
}
