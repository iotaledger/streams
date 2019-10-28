use crate::trits::*;
use crate::spongos::*;
use crate::prng::*;
use crate::poly::*;

/// NTRU public key - 3g(x)/(1+3f(x)) - size.
pub const PK_SIZE: usize = 9216;
/// NTRU private key - f(x) - size.
pub const SK_SIZE: usize = 1024;
/// NTRU session symmetric key size.
pub const KEY_SIZE: usize = crate::spongos::KEY_SIZE;
/// NTRU encrypted key size.
pub const EKEY_SIZE: usize = 9216;
/// NTRU id size.
pub const ID_SIZE: usize = 81;

fn gen_step(f: &mut Poly, g: &mut Poly, h: &mut Poly) -> bool {
    // f := NTT(1+3f)
    f.small_mul3();
    f.small3_add1();
    f.ntt();

    // g := NTT(3g)
    g.small_mul3();
    g.ntt();

    if f.has_inv() && g.has_inv() {
        // h := 3g/(1+3f)
        *h = *f;
        h.inv();
        h.conv(&g);
        h.intt();

        true
    } else {
        false
    }
}

fn gen_r<TW>(prng: &PRNG<TW>, nonce: TritConstSlice<TW>, f: &mut Poly, sk: TritMutSlice<TW>, pk: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(sk.size() == SK_SIZE);
    assert!(pk.size() == PK_SIZE);

    let mut i = Trits::<TW>::zero(81);
    let mut r = Trits::<TW>::zero(2 * SK_SIZE);
    let mut g = Poly::new();
    let mut h = Poly::new();

    loop {
        {
            let nonces = [nonce, i.slice()];
            prng.gens(&nonces, r.mut_slice());
        }
        f.small_from_trits(r.slice().take(SK_SIZE));
        g.small_from_trits(r.slice().drop(SK_SIZE));

        if gen_step(f, &mut g, &mut h) {
            h.to_trits(pk);
            r.slice().take(SK_SIZE).copy(sk);
            break;
        }

        // ignore inc result for now, fail if false
        let _ = i.mut_slice().inc();
    }
}

fn encr_r<TW>(s: &mut Spongos<TW>, h: &mut Poly, r: TritMutSlice<TW>, k: TritConstSlice<TW>, y: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(r.size() == SK_SIZE);
    assert!(k.size() == KEY_SIZE);
    assert!(y.size() == EKEY_SIZE);

    let mut t = Poly::new();

    h.ntt();

    // t(x) := r(x)*h(x)
    t.small_from_trits(r.as_const());
    t.ntt();
    t.conv(&h);
    t.intt();

    // h(x) = AE(r*h;k)
    //TODO: check y size vs t size
    t.to_trits(y);
    //s.init();
    s.absorb(y.as_const());
    s.commit();
    s.encr(k, r.take(KEY_SIZE));
    s.squeeze(r.drop(KEY_SIZE));
    h.small_from_trits(r.as_const());

    // y = r*h + AE(r*h;k)
    t.add(&h);
    t.to_trits(y);
}

fn encr_pk<TW>(s: &mut Spongos<TW>, prng: &PRNG<TW>, pk: TritConstSlice<TW>, n: TritConstSlice<TW>, k: TritConstSlice<TW>, y: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(pk.size() == PK_SIZE);
    assert!(k.size() == KEY_SIZE);
    assert!(y.size() == EKEY_SIZE);

    let mut h = Poly::new();
    let ok = h.from_trits(pk);
    //TODO: return false if bad pk?
    assert!(ok);

    // resuze y slice for random
    let r = y.take(SK_SIZE);
    {
        let nonces = [pk, k, n];
        prng.gens(&nonces, r); // use pk, k, n as nonces
    }
    encr_r(s, &mut h, r, k, y);
}

fn decr_r<TW>(s: &mut Spongos<TW>, f: &Poly, y: TritConstSlice<TW>, k: TritMutSlice<TW>) -> bool where TW: TritWord + Copy {
    assert!(k.size() == KEY_SIZE);
    assert!(y.size() == EKEY_SIZE);

    // f is NTT form
    //f = (poly_coeff_t *)n->f;

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
    let mut kt = Trits::<TW>::zero(SK_SIZE);
    r.round_to_trits(kt.mut_slice());
    r.small_from_trits(kt.slice());

    // t(x) := Y - r(x)
    t.sub(&r);
    let mut rh = Trits::<TW>::zero(EKEY_SIZE);
    t.to_trits(rh.mut_slice());

    // K = AD(rh;kt)
    //spongos_init(s);
    s.absorb(rh.slice());
    s.commit();
    s.decr(kt.slice().take(KEY_SIZE), k);
    let mut m = Trits::<TW>::zero(SK_SIZE - KEY_SIZE);
    s.squeeze(m.mut_slice());
    m.slice() == kt.slice().drop(KEY_SIZE)
}

fn decr_sk<TW>(s: &mut Spongos<TW>, sk: TritConstSlice<TW>, y: TritConstSlice<TW>, k: TritMutSlice<TW>) -> bool where TW: TritWord + Copy {
    assert!(sk.size() == SK_SIZE);
    assert!(k.size() == KEY_SIZE);
    assert!(y.size() == EKEY_SIZE);

    let mut f = Poly::new();
    f.small_from_trits(sk);

    // f := NTT(1+3f)
    f.small_mul3();
    f.small3_add1();
    f.ntt();

    decr_r(s, &f, y, k)
}

pub struct PrivateKey<TW> {
    sk: Trits<TW>,
    f: Poly,
}

pub struct PublicKey<TW> {
    pk: Trits<TW>,
}

pub fn gen<TW>(prng: &PRNG<TW>, nonce: TritConstSlice<TW>) -> (PrivateKey<TW>, PublicKey<TW>) where TW: TritWord + Copy {
    let mut sk = PrivateKey::<TW>{
        sk: Trits::<TW>::zero(SK_SIZE),
        f: Poly::new(),
    };
    let mut pk = PublicKey::<TW>{
        pk: Trits::<TW>::zero(PK_SIZE),
    };

    gen_r(&prng, nonce, &mut sk.f, sk.sk.mut_slice(), pk.pk.mut_slice());
    (sk, pk)
}

impl<TW> PrivateKey<TW> where TW: TritWord + Copy {
    pub fn decr(&self, y: TritConstSlice<TW>, k: TritMutSlice<TW>) -> bool {
        let mut s = Spongos::<TW>::init();
        decr_sk(&mut s, self.sk.slice(), y, k)
    }
}

impl<TW> PublicKey<TW> where TW: TritWord + Copy {
    pub fn encr(&self, prng: &PRNG<TW>, nonce: TritConstSlice<TW>, k: TritConstSlice<TW>, y: TritMutSlice<TW>) {
        let mut s = Spongos::<TW>::init();
        encr_pk(&mut s, &prng, self.pk.slice(), nonce, k, y);
    }
}

#[cfg(test)]
mod test_ntru {
    use super::*;

    #[test]
    fn test_encr_decr() {
        let prng_key = Trits::<Trit>::zero(MAM_PRNG_SECRET_KEY_SIZE);
        let prng = PRNG::<Trit>::init(prng_key.slice());
        let nonce = Trits::<Trit>::zero(15);
        let k = Trits::<Trit>::zero(KEY_SIZE);
        let mut ek = Trits::<Trit>::zero(EKEY_SIZE);
        let mut dek = Trits::<Trit>::zero(KEY_SIZE);

        /*
        let mut sk = PrivateKey::<Trit> {
            sk: Trits::<Trit>::zero(SK_SIZE),
            f: Poly::new(),
        };
        let mut pk = PublicKey::<Trit> {
            pk: Trits::<Trit>::zero(PK_SIZE),
        };
        {
            let mut r = Trits::<Trit>::zero(SK_SIZE);
            r.mut_slice().setTrit(1);
            sk.f.small_from_trits(r.slice());
            let mut g = Poly::new();
            g.small_from_trits(r.slice());
            g.small3_add1();
            g.small3_add1();
            let mut h = Poly::new();

            if gen_step(&mut sk.f, &mut g, &mut h) {
                h.to_trits(pk.pk.mut_slice());
            } else {
                assert!(false);
            }
        }
         */
        let (sk, pk) = gen(&prng, nonce.slice());

        pk.encr(&prng, nonce.slice(), k.slice(), ek.mut_slice());
        let ok = sk.decr(ek.slice(), dek.mut_slice());
        assert!(ok);
        assert!(k == dek);
    }
}
