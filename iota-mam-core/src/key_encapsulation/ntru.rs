use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::hash;

use crate::prng::Prng;
use crate::sponge::{prp::{PRP, Troika}, spongos::SpongosT};
use crate::tbits::{word::{BasicTbitWord, SpongosTbitWord}, trinary::TritWord, TbitSliceT, TbitSliceMutT, TbitsT};

use super::poly::*;

/// NTRU public key - 3g(x)/(1+3f(x)) - size.
pub const PK_SIZE: usize = 9216;

/// NTRU public key id size.
pub const PKID_SIZE: usize = 81;

/// NTRU private key - f(x) - size.
pub const SK_SIZE: usize = 1024;

/// NTRU session symmetric key size.
pub const KEY_SIZE: usize = 243;//crate::spongos::KEY_SIZE;

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
fn gen_r<TW, F>(
    prng: &Prng<TW, F>,
    nonce: TbitSliceT<TW>,
    f: &mut Poly,
    mut sk: TbitSliceMutT<TW>,
    h: &mut Poly,
    mut pk: TbitSliceMutT<TW>,
) -> bool where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(PK_SIZE, pk.size());

    let mut i = TbitsT::zero(81);
    let mut r = TbitsT::zero(2 * SK_SIZE);
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
            //TODO: copy r.slice to sk
            r.slice().take(SK_SIZE).copy(&mut sk);
            break;
        }

        if !i.slice_mut().inc() {
            return false;
        }
    }
    true
}

fn encrypt_with_fo_transform<TW, FO>(h: &Poly, r: &mut TbitSliceMutT<TW>, y: &mut TbitSliceMutT<TW>, fo: FO)
    where
    TW: TritWord,
    FO: FnOnce(TbitSliceT<TW>, &mut TbitSliceMutT<TW>) -> (),
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
        t.to_trits(y);
        fo(y.as_const(), r);

        // y = r*h + AE(r*h;k)
        t.add_small(r.as_const());
        t.to_trits(y);
    }
}

/// Encrypt secret key `k` with NTRU public key `h`, randomness `r` with spongos instance `s` and put the encrypted key into `y`.
fn encrypt_with_randomness<TW, F>(s: &mut SpongosT<TW, F>, h: &Poly, r: &mut TbitSliceMutT<TW>, k: TbitSliceT<TW>, y: &mut TbitSliceMutT<TW>)
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(KEY_SIZE, k.size());
    let fo = |y: TbitSliceT<TW>, r: &mut TbitSliceMutT<TW>| {
        //s.init();
        s.absorb(y);
        s.commit();
        s.encr(k, &mut r.advance(KEY_SIZE));
        s.squeeze(r);
    };
    encrypt_with_fo_transform(h, r, y, fo);
}

/// Create a public key polynomial `h = NTT(pk)` from tbits `pk` and check it (for invertibility).
fn pk_from_trits<TW>(pk: TbitSliceT<TW>) -> Option<Poly>
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

/// Encrypt secret key `k` with NTRU public key `pk`, public polynomial `h = NTT(pk)` using `prng`, nonce `n` and spongos instance `s`. Put encrypted key into `y`.
pub fn encrypt_with_pk<TW, F, G>(
    s: &mut SpongosT<TW, F>,
    prng: &Prng<TW, G>,
    pk: TbitSliceT<TW>,
    h: &Poly,
    n: TbitSliceT<TW>,
    k: TbitSliceT<TW>,
    y: TbitSliceMutT<TW>,
)
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
    G: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(PK_SIZE, pk.size());
    debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert_eq!(EKEY_SIZE, y.size());

    /*
    // Reuse `y` slice for randomness.
    let r = y.take(SK_SIZE);
    {
        // Use pk, k, n as nonces.
        let nonces = [pk, k, n];
        prng.gens(&nonces, r);
    }
    encrypt_with_randomness(s, h, &mut r, k, &mut y);
     */
    assert!(false, "ntru::encrypt_with_pk not implemented");
}

fn decrypt_with_fo_transform<TW, FO>(f: &Poly, y: TbitSliceT<TW>, fo: FO) -> bool
where
    TW: TritWord + SpongosTbitWord,
    FO: FnOnce(TbitSliceT<TW>, TbitSliceT<TW>) -> bool,
{
    debug_assert_eq!(EKEY_SIZE, y.size());

    // f = NTT(1+3f)

    let mut t = Poly::new();
    // t(x) := Y
    if !t.from_trits(y) {
        return false;
    }

    // r(x) := t(x)*(1+3f(x)) (mods 3)
    let mut r = t;
    r.ntt();
    r.conv(&f);
    r.intt();
    let mut kt = TbitsT::zero(SK_SIZE);
    r.round_to_trits(&mut kt.slice_mut());

    // t(x) := Y - r(x)
    t.sub_small(kt.slice());
    let mut rh = TbitsT::zero(EKEY_SIZE);
    t.to_trits(&mut rh.slice_mut());

    // K = AD(rh;kt)
    fo(rh.slice(), kt.slice())
}

/// Try to decrypt encapsulated key `y` with private polynomial `f` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
fn decrypt_with_randomness<TW, F>(s: &mut SpongosT<TW, F>, f: &Poly, y: TbitSliceT<TW>, k: TbitSliceMutT<TW>) -> bool
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(KEY_SIZE, k.size());
    let fo = |rh: TbitSliceT<TW>, kt: TbitSliceT<TW>| -> bool {
        //spongos_init(s);
        s.absorb(rh);
        s.commit();
        s.decr(kt.take(KEY_SIZE), k);
        s.squeeze_eq(kt.drop(KEY_SIZE))
    };
    decrypt_with_fo_transform(f, y, fo)
}

/// Try to decrypt encapsulated key `y` with private key `sk` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
pub fn decrypt_with_sk<TW, F>(s: &mut SpongosT<TW, F>, sk: TbitSliceT<TW>, y: TbitSliceT<TW>, k: TbitSliceMutT<TW>) -> bool
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(KEY_SIZE, k.size());
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
pub struct PrivateKeyT<TW> {
    sk: TbitsT<TW>,
    f: Poly, // NTT(1+3f)
}

/// Public key object, contains trinary representation `pk` of public polynomial
/// as well as it's NTT form in `h`.
#[derive(Clone)]
pub struct PublicKeyT<TW> {
    pk: TbitsT<TW>,
    h: Poly, // NTT(3g/(1+3f))
}

/// Default implementation for PublicKey. Note, this object is not valid and can't be
/// used for encapsulating keys. This instance exists in order to simplify deserialization
/// of public keys. Once public key trits have been deserialized the object must be `validate`d. If the `validate` method returns `false` then the object is invalid.
/// Otherwise it's valid and can be used for encapsulating secrets.
//TODO: Introduce PrePublicKey with Default implementation and `fn validate(self) -> Option<PublicKey>`.
impl<TW> Default for PublicKeyT<TW>
    where
    TW: BasicTbitWord,
{
    fn default() -> Self {
        Self {
            pk: TbitsT::zero(PK_SIZE),
            h: Poly::new(),
        }
    }
}

/*
impl<TW> fmt::Display for PublicKeyT<TW>
    where
    TW: TritWord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}
 */

impl<TW> fmt::Debug for PublicKeyT<TW>
    where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.pk)
    }
}

impl<TW> PartialEq for PublicKeyT<TW>
    where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}
impl<TW> Eq for PublicKeyT<TW>
    where
    TW: BasicTbitWord,
{}

/// Same implementation as for Pkid.
/// The main property: `pk1 == pk2 => hash(pk1) == hash(pk2)` holds.
impl<TW> hash::Hash for PublicKeyT<TW>
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
impl<TW> Borrow<PkidT<TW>> for PublicKeyT<TW> {
    fn borrow(&self) -> &PkidT<TW> {
        unsafe { std::mem::transmute(self.tbits()) }
    }
}

/// Thin wrapper around Tbits which contains either a full public key or the first `PKID_SIZE` of the public key.
pub struct PkidT<TW>(pub TbitsT<TW>);

impl<TW> PkidT<TW> {
    pub fn tbits(&self) -> &TbitsT<TW> {
        &self.0
    }
    pub fn tbits_mut(&mut self) -> &mut TbitsT<TW> {
        &mut self.0
    }
}

impl<TW> AsRef<TbitsT<TW>> for PkidT<TW> {
    fn as_ref(&self) -> &TbitsT<TW> {
        &self.0
    }
}

impl<TW> AsRef<PkidT<TW>> for TbitsT<TW> {
    fn as_ref(&self) -> &PkidT<TW> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<TW> PartialEq for PkidT<TW>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.tbits().slice().take(PKID_SIZE) == other.tbits().slice().take(PKID_SIZE)
    }
}

impl<TW> Eq for PkidT<TW>
where
    TW: BasicTbitWord,
{}

/// Hash of public key identifier (the first `PKID_SIZE` tbits of the public key).
/// This is implemented
/// `k1 == k2 -> hash(k1) == hash(k2)`
impl<TW> hash::Hash for PkidT<TW>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.tbits().slice().take(PKID_SIZE)).hash(state);
    }
}

/// Generate NTRU keypair with `prng` and `nonce`.
pub fn gen_keypair<TW, F>(prng: &Prng<TW, F>, nonce: TbitSliceT<TW>) -> (PrivateKeyT<TW>, PublicKeyT<TW>)
    where
    TW: TritWord + SpongosTbitWord,
    F: PRP<TW> + Clone + Default,
{
    let mut sk = PrivateKeyT {
        sk: TbitsT::zero(SK_SIZE),
        f: Poly::new(),
    };
    let mut pk = PublicKeyT {
        pk: TbitsT::zero(PK_SIZE),
        h: Poly::new(),
    };

    let ok = gen_r(
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

impl<TW> PrivateKeyT<TW>
where
    TW: TritWord + SpongosTbitWord,
{
    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using spongos instance `s`.
    pub fn decrypt_with_s<F>(&self, s: &mut SpongosT<TW, F>, y: TbitSliceT<TW>, k: TbitSliceMutT<TW>) -> bool
        where
        F: PRP<TW> + Clone + Default,
    {
        decrypt_with_sk(s, self.sk.slice(), y, k)
    }

    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using new spongos instance.
    pub fn decrypt_with_troika(&self, y: TbitSliceT<TW>, k: TbitSliceMutT<TW>) -> bool {
        let mut s = SpongosT::<TW, Troika>::init();
        self.decrypt_with_s(&mut s, y, k)
    }
}

impl<TW> PublicKeyT<TW>
{
    /// Public polinomial tbits.
    pub fn tbits(&self) -> &TbitsT<TW> {
        &self.pk
    }

    /// Public polinomial tbits, once public key has been modified it must be `validate`d.
    pub fn tbits_mut(&mut self) -> &mut TbitsT<TW> {
        &mut self.pk
    }
}

impl<TW> PublicKeyT<TW>
where
    TW: BasicTbitWord,
{
    /// Returns the actual Pkid value trimmed to PKID_SIZE, not the fake borrowed one.
    pub fn get_pkid(&self) -> PkidT<TW> {
        PkidT(TbitsT::from_slice(self.tbits().slice().take(PKID_SIZE)))
    }

    pub fn cmp_pkid(&self, pkid: &PkidT<TW>) -> bool {
        self.pk.size() == PK_SIZE
            && pkid.tbits().size() == PKID_SIZE
            && self.pk.slice().take(PKID_SIZE) == pkid.tbits().slice()
    }

    /// Return public polinomial tbits slice.
    pub fn slice(&self) -> TbitSliceT<TW> {
        self.pk.slice()
    }

    /// Public key identifier -- the first `PKID_SIZE` tbits of the public key.
    pub fn id(&self) -> TbitSliceT<TW> {
        self.pk.slice().take(PKID_SIZE)
    }
}

impl<TW> PublicKeyT<TW>
where
    TW: TritWord,
{
    /// Try to create `PublicKey` object from tbits `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_trits(pk: TbitsT<TW>) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk.slice())?;
            Some(PublicKeyT { pk, h })
        } else {
            None
        }
    }

    /// Try to create `PublicKey` object from slice `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_slice(pk: TbitSliceT<TW>) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk)?;
            Some(PublicKeyT {
                pk: TbitsT::from_slice(pk),
                h,
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

impl<TW> PublicKeyT<TW>
where
    TW: TritWord + SpongosTbitWord,
{
    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using spongos instance `s` and put "capsule" into `y`.
    pub fn encrypt_with_s<F, G>(
        &self,
        s: &mut SpongosT<TW, F>,
        prng: &Prng<TW, G>,
        nonce: TbitSliceT<TW>,
        k: TbitSliceT<TW>,
        y: TbitSliceMutT<TW>,
    )
        where
        F: PRP<TW> + Clone + Default,
        G: PRP<TW> + Clone + Default,
    {
        encrypt_with_pk(s, prng, self.pk.slice(), &self.h, nonce, k, y);
    }

    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using new spongos instance and put "capsule" into `y`.
    pub fn encrypt_with_troika<G>(&self, prng: &Prng<TW, G>, nonce: TbitSliceT<TW>, k: TbitSliceT<TW>, y: TbitSliceMutT<TW>)
        where
        G: PRP<TW> + Clone + Default,
    {
        let mut s = SpongosT::<TW, Troika>::init();
        self.encrypt_with_s(&mut s, prng, nonce, k, y);
    }
}

/// Container for NTRU public keys.
pub type NtruPksT<TW> = HashSet<PublicKeyT<TW>>;

/// Entry in a container, just a convenience type synonym.
pub type INtruPkT<'a, TW> = &'a PublicKeyT<TW>;

/// Container (set) of NTRU public key identifiers.
pub type NtruPkidsT<TW> = Vec<PkidT<TW>>;

/// Select only NTRU public keys with given identifiers.
pub fn filter_ntru_pks<'a, TW>(ntru_pks: &'a NtruPksT<TW>, ntru_pkids: &'_ NtruPkidsT<TW>) -> Vec<INtruPkT<'a, TW>>
    where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    ntru_pkids
        .iter()
        .filter_map(|pkid| ntru_pks.get(pkid))
        .collect::<Vec<INtruPkT<'a, TW>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbits::trinary::Trit;
    use crate::tbits::binary::Byte;
    use crate::sponge::prp::Troika;

    fn encrypt_decrypt_tbits<TW, F, G>()
        where
        TW: TritWord + SpongosTbitWord,
        F: PRP<TW> + Clone + Default,
        G: PRP<TW> + Clone + Default,
    {
        let prng_key = TbitsT::<TW>::zero(crate::prng::KEY_SIZE);
        let prng = Prng::<TW, F>::init(prng_key.slice());
        let nonce = TbitsT::<TW>::zero(15);
        let k = TbitsT::<TW>::zero(KEY_SIZE);
        let mut ek = TbitsT::<TW>::zero(EKEY_SIZE);
        let mut dek = TbitsT::<TW>::zero(KEY_SIZE);

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
            let mut s = SpongosT::<TW, F>::init();
            pk.encrypt_with_s(&mut s, &prng, nonce.slice(), k.slice(), ek.slice_mut());
        }

        let ok = {
            let mut s = SpongosT::<TW, F>::init();
            sk.decrypt_with_s(&mut s, ek.slice(), dek.slice_mut())
        };
        assert!(ok);
        assert!(k == dek);
    }

    #[test]
    fn encrypt_decrypt_b1t1() {
        encrypt_decrypt_tbits::<Trit, Troika, Troika>();
    }

    #[test]
    fn encrypt_decrypt_b1b8() {
        //encrypt_decrypt_tbits::<Byte, KeccakF1600, KeccakF1600>();
    }
}
