use super::{
    prp::PRP,
    spongos::*,
};
use crate::prelude::Vec;

fn bytes_spongosn<F>(n: usize)
where
    F: PRP,
{
    let mut rng = Spongos::<F>::init();
    rng.absorb_buf(&vec![0; n]);
    rng.commit();
    let k = rng.squeeze_buf(n);
    let p = rng.squeeze_buf(n);
    let x = rng.squeeze_buf(n);
    let y: Vec<u8>;
    let mut z: Vec<u8>;
    let t: Vec<u8>;
    let u: Vec<u8>;
    let t2: Vec<u8>;
    let t3: Vec<u8>;

    {
        let mut s = Spongos::<F>::init();
        s.absorb_buf(&k);
        s.absorb_buf(&p);
        s.commit();
        y = s.encrypt_buf(&x);
        s.commit();
        t = s.squeeze_buf(n);
        t2 = s.squeeze_buf(n);
        t3 = s.squeeze_buf(n);
    }

    {
        let mut s = Spongos::<F>::init();
        s.absorb_buf(&k);
        s.absorb_buf(&p);
        s.commit();
        z = y;
        s.decrypt_buf_mut(&mut z);
        s.commit();
        u = s.squeeze_buf(n);
        assert!(s.squeeze_eq_buf(&t2));
        assert!(s.squeeze_eq_buf(&t3));
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

fn slice_spongosn<F>(n: usize)
where
    F: PRP,
{
    let mut k = vec![0_u8; n];
    let mut p = vec![0_u8; n];
    let mut x = vec![0_u8; n];
    let mut y = vec![0_u8; n];
    let mut z = vec![0_u8; n];
    let mut t = vec![0_u8; n];
    let mut u = vec![0_u8; n];
    let mut t23 = vec![0_u8; n + n];

    let mut s: Spongos<F>;
    {
        s = Spongos::init();
        s.absorb(&k[..]);
        s.commit();
        s.squeeze(&mut k[..]);
        s.squeeze(&mut p[..]);
        s.squeeze(&mut x[..]);
    }

    {
        s = Spongos::init();
        s.absorb(&k[..]);
        s.absorb(&p[..]);
        s.commit();
        s.encrypt(&x[..], &mut y[..]);
        s.commit();
        s.squeeze(&mut t[..]);
        s.squeeze(&mut t23[..n]);
        s.squeeze(&mut t23[n..]);
    }

    {
        s = Spongos::init();
        s.absorb(&k[..]);
        s.absorb(&p[..]);
        s.commit();
        s.decrypt(&y[..], &mut z[..]);
        s.commit();
        s.squeeze(&mut u[..]);
        assert!(s.squeeze_eq(&t23[..n]));
        assert!(s.squeeze_eq(&t23[n..]));
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

pub fn bytes_with_size_boundary_cases<F>()
where
    F: PRP,
{
    for i in 1..100 {
        bytes_spongosn::<F>(i);
    }
    bytes_spongosn::<F>(F::RATE / 2 - 1);
    bytes_spongosn::<F>(F::RATE / 2);
    bytes_spongosn::<F>(F::RATE / 2 + 1);
    bytes_spongosn::<F>(F::RATE - 1);
    bytes_spongosn::<F>(F::RATE);
    bytes_spongosn::<F>(F::RATE + 1);
    bytes_spongosn::<F>(F::RATE * 2 - 1);
    bytes_spongosn::<F>(F::RATE * 2);
    bytes_spongosn::<F>(F::RATE * 2 + 1);
    bytes_spongosn::<F>(F::RATE * 5);
}

pub fn slices_with_size_boundary_cases<F>()
where
    F: PRP,
{
    for i in 1..100 {
        slice_spongosn::<F>(i);
    }
    slice_spongosn::<F>(F::RATE / 2 - 1);
    slice_spongosn::<F>(F::RATE / 2);
    slice_spongosn::<F>(F::RATE / 2 + 1);
    slice_spongosn::<F>(F::RATE - 1);
    slice_spongosn::<F>(F::RATE);
    slice_spongosn::<F>(F::RATE + 1);
    slice_spongosn::<F>(F::RATE * 2 - 1);
    slice_spongosn::<F>(F::RATE * 2);
    slice_spongosn::<F>(F::RATE * 2 + 1);
    slice_spongosn::<F>(F::RATE * 5);
}

pub fn encrypt_decrypt_n<F>(n: usize)
where
    F: PRP,
{
    let mut s = Spongos::<F>::init();
    // s.absorb_buf(&Tbits::cycle_str(Spongos::<F>::KEY_SIZE, "KEY"));
    s.absorb_buf(&vec![0; Spongos::<F>::KEY_SIZE]);
    s.commit();

    // let x = Tbits::cycle_str(n, "TEXT");
    let x = s.clone().squeeze_buf(n);
    {
        let mut s2 = s.clone();
        let mut s3 = s.clone();
        let mut s4 = s.clone();

        let ex = s.encrypt_buf(&x);
        s.commit();
        let tag = s.squeeze_buf(F::RATE);

        let dex = s2.decrypt_buf(&ex);
        assert_eq!(x, dex);
        s2.commit();
        assert_eq!(tag, s2.squeeze_buf(F::RATE));

        let mut x2 = x.clone();
        s3.encrypt_buf_mut(&mut x2);
        assert_eq!(ex, x2);
        s3.commit();
        assert_eq!(tag, s3.squeeze_buf(F::RATE));

        s4.decrypt_buf_mut(&mut x2);
        assert_eq!(x, x2);
        s4.commit();
        assert_eq!(tag, s4.squeeze_buf(F::RATE));
    }
}

// #[test]
// fn inner() {
// let mut s = Spongos::init();
// s.absorb_trits(&Trits::from_str("ABC").unwrap());
// s.commit();
// let mut s2 = Spongos::from_inner_trits(&s.to_inner_trits());
//
// s.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
// s.commit();
// s2.absorb_trits(&Trits::cycle_str(RATE + 1, "DEF"));
// s2.commit();
// assert_eq!(s.squeeze_trits(RATE + 1), s2.squeeze_trits(RATE + 1));
// }
