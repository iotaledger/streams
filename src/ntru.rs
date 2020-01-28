use std::fmt;

use crate::poly::*;
use crate::prng::PRNG;
use crate::spongos::Spongos;
use crate::trits::{TritSlice, TritSliceMut, Trits};

/// NTRU public key - 3g(x)/(1+3f(x)) - size.
pub const PK_SIZE: usize = 9216;

/// NTRU public key id size.
pub const PKID_SIZE: usize = 81;

/// NTRU private key - f(x) - size.
pub const SK_SIZE: usize = 1024;

/// NTRU session symmetric key size.
pub const KEY_SIZE: usize = crate::spongos::KEY_SIZE;

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
fn gen_r(
    prng: &PRNG,
    nonce: TritSlice,
    f: &mut Poly,
    sk: TritSliceMut,
    h: &mut Poly,
    pk: TritSliceMut,
) -> bool {
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(PK_SIZE, pk.size());

    let mut i = Trits::zero(81);
    let mut r = Trits::zero(2 * SK_SIZE);
    let mut g = Poly::new();

    loop {
        {
            let nonces = [nonce, i.slice()];
            prng.gens(&nonces, r.slice_mut());
        }
        f.small_from_trits(r.slice().take(SK_SIZE));
        g.small_from_trits(r.slice().drop(SK_SIZE));

        if gen_step(f, &mut g, h) {
            //h.intt();
            g = *h;
            g.intt();
            g.to_trits(pk);
            r.slice().take(SK_SIZE).copy(sk);
            break;
        }

        if !i.slice_mut().inc() {
            return false;
        }
    }
    true
}

fn encr_fo<FO>(h: &Poly, r: TritSliceMut, y: TritSliceMut, mut fo: FO)
where
    FO: FnMut(TritSlice, TritSliceMut) -> (),
{
    debug_assert_eq!(SK_SIZE, r.size());
    debug_assert_eq!(EKEY_SIZE, y.size());

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

/// Encrypt secret key `k` with NTRU public key `h`, randomness `r` with spongos instance `s` and put the encrypted key into `y`.
fn encr_r(s: &mut Spongos, h: &Poly, r: TritSliceMut, k: TritSlice, y: TritSliceMut) {
    debug_assert_eq!(KEY_SIZE, k.size());
    let fo = |y: TritSlice, r: TritSliceMut| {
        //s.init();
        s.absorb(y);
        s.commit();
        s.encr(k, r.take(KEY_SIZE));
        s.squeeze(r.drop(KEY_SIZE));
    };
    encr_fo(h, r, y, fo);
}

/// Create a public key polynomial `h = NTT(pk)` from trits `pk` and check it (for invertibility).
fn pk_from_trits(pk: TritSlice) -> Option<Poly> {
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
pub fn encr_pk(
    s: &mut Spongos,
    prng: &PRNG,
    pk: TritSlice,
    h: &Poly,
    n: TritSlice,
    k: TritSlice,
    y: TritSliceMut,
) {
    debug_assert_eq!(PK_SIZE, pk.size());
    debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert_eq!(EKEY_SIZE, y.size());

    // Reuse `y` slice for randomness.
    let r = y.take(SK_SIZE);
    {
        // Use pk, k, n as nonces.
        let nonces = [pk, k, n];
        prng.gens(&nonces, r);
    }
    encr_r(s, h, r, k, y);
}

fn decr_fo<FO>(f: &Poly, y: TritSlice, mut fo: FO) -> bool
where
    FO: FnMut(TritSlice, TritSlice) -> bool,
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
    let mut kt = Trits::zero(SK_SIZE);
    r.round_to_trits(kt.slice_mut());

    // t(x) := Y - r(x)
    t.sub_small(kt.slice());
    let mut rh = Trits::zero(EKEY_SIZE);
    t.to_trits(rh.slice_mut());

    // K = AD(rh;kt)
    fo(rh.slice(), kt.slice())
}

/// Try to decrypt encapsulated key `y` with private polynomial `f` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
fn decr_r(s: &mut Spongos, f: &Poly, y: TritSlice, k: TritSliceMut) -> bool {
    debug_assert_eq!(KEY_SIZE, k.size());
    let fo = |rh: TritSlice, kt: TritSlice| -> bool {
        //spongos_init(s);
        s.absorb(rh);
        s.commit();
        s.decr(kt.take(KEY_SIZE), k);
        s.squeeze_eq(kt.drop(KEY_SIZE))
    };
    decr_fo(f, y, fo)
}

/// Try to decrypt encapsulated key `y` with private key `sk` using spongos instance `s`.
/// In case of success `k` contains decrypted secret key.
pub fn decr_sk(s: &mut Spongos, sk: TritSlice, y: TritSlice, k: TritSliceMut) -> bool {
    debug_assert_eq!(SK_SIZE, sk.size());
    debug_assert_eq!(KEY_SIZE, k.size());
    debug_assert_eq!(EKEY_SIZE, y.size());

    let mut f = Poly::new();
    f.small_from_trits(sk);

    // f := NTT(1+3f)
    f.small_mul3();
    f.small3_add1();
    f.ntt();

    decr_r(s, &f, y, k)
}

/// Private key object, contains secret trits `sk` and polynomial `f = NTT(1+3sk)`
/// which serves as a precomputed value during decryption.
#[derive(Clone)]
pub struct PrivateKey {
    sk: Trits,
    f: Poly, // NTT(1+3f)
}

/// Public key object, contains trinary representation `pk` of public polynomial
/// as well as it's NTT form in `h`.
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) pk: Trits,
    h: Poly, // NTT(3g/(1+3f))
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.pk)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}
impl Eq for PublicKey {}

pub type Pkid = Trits;

/// Generate NTRU keypair with `prng` and `nonce`.
pub fn gen(prng: &PRNG, nonce: TritSlice) -> (PrivateKey, PublicKey) {
    let mut sk = PrivateKey {
        sk: Trits::zero(SK_SIZE),
        f: Poly::new(),
    };
    let mut pk = PublicKey {
        pk: Trits::zero(PK_SIZE),
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

impl PrivateKey {
    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using spongos instance `s`.
    pub fn decr_with_s(&self, s: &mut Spongos, y: TritSlice, k: TritSliceMut) -> bool {
        decr_sk(s, self.sk.slice(), y, k)
    }

    /// Decapsulate secret key `k` from "capsule" `y` with private key `self` using new spongos instance.
    pub fn decr(&self, y: TritSlice, k: TritSliceMut) -> bool {
        let mut s = Spongos::init();
        self.decr_with_s(&mut s, y, k)
    }
}

impl PublicKey {
    /// Return public polinomial trits slice.
    pub fn trits(&self) -> TritSlice {
        self.pk.slice()
    }

    /// Try to create `PublicKey` object from trits `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_trits(pk: Trits) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk.slice())?;
            Some(PublicKey { pk, h })
        } else {
            None
        }
    }

    /// Try to create `PublicKey` object from slice `pk`. Fails in case `pk` has bad size
    /// or corresponding polynomial is not invertible.
    pub fn from_slice(pk: TritSlice) -> Option<Self> {
        if pk.size() == PK_SIZE {
            let h = pk_from_trits(pk)?;
            Some(PublicKey {
                pk: Trits::from_slice(pk),
                h,
            })
        } else {
            None
        }
    }

    /// Precompute polynomial `h = NTT(pk)` and check for invertibility.
    pub(crate) fn validate(&mut self) -> bool {
        if let Some(h) = pk_from_trits(self.pk.slice()) {
            self.h = h;
            true
        } else {
            false
        }
    }

    /// Public key identifier -- the first `PKID_SIZE` trits of the public key.
    pub fn id(&self) -> TritSlice {
        self.pk.slice().take(PKID_SIZE)
    }

    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using spongos instance `s` and put "capsule" into `y`.
    pub fn encr_with_s(
        &self,
        s: &mut Spongos,
        prng: &PRNG,
        nonce: TritSlice,
        k: TritSlice,
        y: TritSliceMut,
    ) {
        encr_pk(s, prng, self.pk.slice(), &self.h, nonce, k, y);
    }

    /// Encapsulate key `k` with `prng`, `nonce`, public key `self` using new spongos instance and put "capsule" into `y`.
    pub fn encr(&self, prng: &PRNG, nonce: TritSlice, k: TritSlice, y: TritSliceMut) {
        let mut s = Spongos::init();
        self.encr_with_s(&mut s, prng, nonce, k, y);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encr_decr() {
        let prng_key = Trits::zero(crate::prng::KEY_SIZE);
        let prng = PRNG::init(prng_key.slice());
        let nonce = Trits::zero(15);
        let k = Trits::zero(KEY_SIZE);
        let mut ek = Trits::zero(EKEY_SIZE);
        let mut dek = Trits::zero(KEY_SIZE);

        /*
        let mut sk = PrivateKey {
            sk: Trits::zero(SK_SIZE),
            f: Poly::new(),
        };
        let mut pk = PublicKey {
            pk: Trits::zero(PK_SIZE),
        };
        {
            let mut r = Trits::zero(SK_SIZE);
            r.slice_mut().setTrit(1);
            sk.f.small_from_trits(r.slice());
            let mut g = Poly::new();
            g.small_from_trits(r.slice());
            g.small3_add1();
            g.small3_add1();
            let mut h = Poly::new();

            if gen_step(&mut sk.f, &mut g, &mut h) {
                h.to_trits(pk.pk.slice_mut());
            } else {
                debug_assert!(false);
            }
        }
         */
        let (sk, pk) = gen(&prng, nonce.slice());

        pk.encr(&prng, nonce.slice(), k.slice(), ek.slice_mut());
        let ok = sk.decr(ek.slice(), dek.slice_mut());
        assert!(ok);
        assert!(k == dek);
    }
}
