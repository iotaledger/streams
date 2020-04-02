use std::fmt;
//use std::str::FromStr;
use super::prp::PRP;
use super::spongos::*;
use crate::tbits::{word::SpongosTbitWord, Tbits};

#[cfg(test)]
use super::prp::troika::Troika;
#[cfg(test)]
use crate::tbits::trinary::Trit;

fn tbits_spongosn<TW, F>(n: usize)
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    let mut rng = Spongos::<TW, F>::init();
    rng.absorb_tbits(&Tbits::zero(n));
    rng.commit();
    let k = rng.squeeze_tbits(n);
    let p = rng.squeeze_tbits(n);
    let x = rng.squeeze_tbits(n);
    let y: Tbits<TW>;
    let mut z: Tbits<TW>;
    let t: Tbits<TW>;
    let u: Tbits<TW>;

    {
        let mut s = Spongos::<TW, F>::init();
        s.absorb_tbits(&k);
        s.absorb_tbits(&p);
        s.commit();
        y = s.encrypt_tbits(&x);
        s.commit();
        t = s.squeeze_tbits(n);
    }

    {
        let mut s = Spongos::<TW, F>::init();
        s.absorb_tbits(&k);
        s.absorb_tbits(&p);
        s.commit();
        z = y;
        s.decrypt_mut_tbits(&mut z);
        s.commit();
        u = s.squeeze_tbits(n);
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

fn slice_spongosn<TW, F>(n: usize)
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    let mut k = Tbits::zero(n);
    let mut p = Tbits::zero(n);
    let mut x = Tbits::zero(n);
    let mut y = Tbits::zero(n);
    let mut z = Tbits::zero(n);
    let mut t = Tbits::zero(n);
    let mut u = Tbits::zero(n);

    let mut s: Spongos<TW, F>;
    {
        s = Spongos::init();
        s.absorb(k.slice());
        s.commit();
        s.squeeze2(k.slice_mut());
        s.squeeze2(p.slice_mut());
        s.squeeze2(x.slice_mut());
    }

    {
        s = Spongos::init();
        s.absorb(k.slice());
        s.absorb(p.slice());
        s.commit();
        s.encrypt2(x.slice(), y.slice_mut());
        s.commit();
        s.squeeze2(t.slice_mut());
    }

    {
        s = Spongos::init();
        s.absorb(k.slice());
        s.absorb(p.slice());
        s.commit();
        s.decrypt2(y.slice(), z.slice_mut());
        s.commit();
        s.squeeze2(u.slice_mut());
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

pub fn tbits_with_size_boundary_cases<TW, F>()
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    for i in 1..100 {
        tbits_spongosn::<TW, F>(i);
    }
    tbits_spongosn::<TW, F>(F::RATE / 2 - 1);
    tbits_spongosn::<TW, F>(F::RATE / 2);
    tbits_spongosn::<TW, F>(F::RATE / 2 + 1);
    tbits_spongosn::<TW, F>(F::RATE - 1);
    tbits_spongosn::<TW, F>(F::RATE);
    tbits_spongosn::<TW, F>(F::RATE + 1);
    tbits_spongosn::<TW, F>(F::RATE * 2 - 1);
    tbits_spongosn::<TW, F>(F::RATE * 2);
    tbits_spongosn::<TW, F>(F::RATE * 2 + 1);
    tbits_spongosn::<TW, F>(F::RATE * 5);
}

pub fn slices_with_size_boundary_cases<TW, F>()
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    for i in 1..100 {
        slice_spongosn::<TW, F>(i);
    }
    slice_spongosn::<TW, F>(F::RATE / 2 - 1);
    slice_spongosn::<TW, F>(F::RATE / 2);
    slice_spongosn::<TW, F>(F::RATE / 2 + 1);
    slice_spongosn::<TW, F>(F::RATE - 1);
    slice_spongosn::<TW, F>(F::RATE);
    slice_spongosn::<TW, F>(F::RATE + 1);
    slice_spongosn::<TW, F>(F::RATE * 2 - 1);
    slice_spongosn::<TW, F>(F::RATE * 2);
    slice_spongosn::<TW, F>(F::RATE * 2 + 1);
    slice_spongosn::<TW, F>(F::RATE * 5);
}

pub fn encrypt_decrypt_n<TW, F>(n: usize)
where
    TW: SpongosTbitWord,
    TW::Tbit: fmt::Display,
    F: PRP<TW> + Default + Clone,
{
    let mut s = Spongos::<TW, F>::init();
    //s.absorb_tbits(&Tbits::cycle_str(Spongos::<TW, F>::KEY_SIZE, "KEY"));
    s.absorb_tbits(&Tbits::zero(Spongos::<TW, F>::KEY_SIZE));
    s.commit();

    //let x = Tbits::cycle_str(n, "TEXT");
    let x = s.clone().squeeze_tbits(n);
    {
        let mut s2 = s.clone();
        let mut s3 = s.clone();
        let mut s4 = s.clone();

        let ex = s.encrypt_tbits(&x);
        s.commit();
        let tag = s.squeeze_tbits(F::RATE);

        let dex = s2.decrypt_tbits(&ex);
        assert_eq!(x, dex);
        s2.commit();
        assert_eq!(tag, s2.squeeze_tbits(F::RATE));

        let mut x2 = x.clone();
        s3.encrypt_mut_tbits(&mut x2);
        assert_eq!(ex, x2);
        s3.commit();
        assert_eq!(tag, s3.squeeze_tbits(F::RATE));

        s4.decrypt_mut_tbits(&mut x2);
        assert_eq!(x, x2);
        s4.commit();
        assert_eq!(tag, s4.squeeze_tbits(F::RATE));
    }
}

#[test]
fn tbits_with_size_boundary_cases_troika() {
    tbits_with_size_boundary_cases::<Trit, Troika>();
}

#[test]
fn slices_with_size_boundary_cases_troika() {
    slices_with_size_boundary_cases::<Trit, Troika>();
}

#[test]
fn encrypt_decrypt_troika() {
    const RATE: usize = <Troika as PRP<Trit>>::RATE;
    encrypt_decrypt_n::<Trit, Troika>(27);
    encrypt_decrypt_n::<Trit, Troika>(RATE);
    encrypt_decrypt_n::<Trit, Troika>(RATE - 28);
    encrypt_decrypt_n::<Trit, Troika>(RATE + 28);
    encrypt_decrypt_n::<Trit, Troika>(2 * RATE);
}

/*
#[test]
fn inner() {
    let mut s = Spongos::init();
    s.absorb_trits(&Trits::from_str("ABC").unwrap());
    s.commit();
    let mut s2 = Spongos::from_inner_trits(&s.to_inner_trits());

    s.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
    s.commit();
    s2.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
    s2.commit();
    assert_eq!(s.squeeze_trits(RATE + 1), s2.squeeze_trits(RATE + 1));
}
 */
