use alloc::vec::Vec;

use generic_array::typenum::Unsigned;

use super::{
    prp::{
        keccak::KeccakF1600,
        PRP,
    },
    spongos::Spongos,
};

fn bytes_spongosn<F: PRP + Default>(n: usize) {
    let mut rng = Spongos::<F>::init();
    rng.absorb(&vec![0; 10]);
    rng.commit();
    let k = rng.squeeze_n(n);
    let p = rng.squeeze_n(n);
    let x = rng.squeeze_n(n);
    let y: Vec<u8>;
    let mut z: Vec<u8>;
    let t: Vec<u8>;
    let u: Vec<u8>;
    let t2: Vec<u8>;
    let t3: Vec<u8>;

    let mut s = Spongos::<F>::init();
    s.absorb(&k);
    s.absorb(&p);
    s.commit();
    y = s.encrypt_n(&x).unwrap();
    s.commit();
    t = s.squeeze_n(n);
    t2 = s.squeeze_n(n);
    t3 = s.squeeze_n(n);

    let mut s = Spongos::<F>::init();
    s.absorb(&k);
    s.absorb(&p);
    s.commit();
    z = y;
    s.decrypt_inplace(&mut z);
    s.commit();
    u = s.squeeze_n(n);
    assert!(s.squeeze_eq(&t2));
    assert!(s.squeeze_eq(&t3));

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

fn slice_spongosn<F: PRP + Default>(n: usize) {
    let mut k = vec![0_u8; n];
    let mut p = vec![0_u8; n];
    let mut x = vec![0_u8; n];
    let mut y = vec![0_u8; n];
    let mut z = vec![0_u8; n];
    let mut t = vec![0_u8; n];
    let mut u = vec![0_u8; n];
    let mut t23 = vec![0_u8; n + n];

    let mut s: Spongos<F>;
    s = Spongos::init();
    s.absorb(&k[..]);
    s.commit();
    s.squeeze_mut(&mut k[..]);
    s.squeeze_mut(&mut p[..]);
    s.squeeze_mut(&mut x[..]);

    s = Spongos::init();
    s.absorb(&k[..]);
    s.absorb(&p[..]);
    s.commit();
    s.encrypt_mut(&x[..], &mut y[..]).unwrap();
    s.commit();
    s.squeeze_mut(&mut t[..]);
    s.squeeze_mut(&mut t23[..n]);
    s.squeeze_mut(&mut t23[n..]);

    s = Spongos::init();
    s.absorb(&k[..]);
    s.absorb(&p[..]);
    s.commit();
    s.decrypt_mut(&y[..], &mut z[..]).unwrap();
    s.commit();
    s.squeeze_mut(&mut u[..]);
    assert!(s.squeeze_eq(&t23[..n]));
    assert!(s.squeeze_eq(&t23[n..]));

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

#[test]
fn bytes_with_size_boundary_cases() {
    let rate = <KeccakF1600 as PRP>::RateSize::USIZE;
    for i in 1..100 {
        bytes_spongosn::<KeccakF1600>(i);
        encrypt_decrypt_n::<KeccakF1600>(i);
    }
    bytes_spongosn::<KeccakF1600>(rate / 2 - 1);
    bytes_spongosn::<KeccakF1600>(rate / 2);
    bytes_spongosn::<KeccakF1600>(rate / 2 + 1);
    bytes_spongosn::<KeccakF1600>(rate - 1);
    bytes_spongosn::<KeccakF1600>(rate);
    bytes_spongosn::<KeccakF1600>(rate + 1);
    bytes_spongosn::<KeccakF1600>(rate * 2 - 1);
    bytes_spongosn::<KeccakF1600>(rate * 2);
    bytes_spongosn::<KeccakF1600>(rate * 2 + 1);
    bytes_spongosn::<KeccakF1600>(rate * 5);
}

#[test]
fn slices_with_size_boundary_cases() {
    let rate = <KeccakF1600 as PRP>::RateSize::USIZE;
    for i in 1..100 {
        slice_spongosn::<KeccakF1600>(i);
        encrypt_decrypt_n::<KeccakF1600>(i);
    }
    slice_spongosn::<KeccakF1600>(rate / 2 - 1);
    slice_spongosn::<KeccakF1600>(rate / 2);
    slice_spongosn::<KeccakF1600>(rate / 2 + 1);
    slice_spongosn::<KeccakF1600>(rate - 1);
    slice_spongosn::<KeccakF1600>(rate);
    slice_spongosn::<KeccakF1600>(rate + 1);
    slice_spongosn::<KeccakF1600>(rate * 2 - 1);
    slice_spongosn::<KeccakF1600>(rate * 2);
    slice_spongosn::<KeccakF1600>(rate * 2 + 1);
    slice_spongosn::<KeccakF1600>(rate * 5);
}

fn encrypt_decrypt_n<F: PRP + Default + Clone>(n: usize) {
    let rate = F::RateSize::USIZE;
    let mut s = Spongos::<F>::init();
    s.absorb(&vec![1; 32]);
    s.commit();

    let x = s.clone().squeeze_n(n);
    let mut s2 = s.clone();
    let mut s3 = s.clone();
    let mut s4 = s.clone();

    let ex = s.encrypt_n(&x).unwrap();
    s.commit();
    let tag = s.squeeze_n(rate);

    let dex = s2.decrypt_n(&ex).unwrap();
    assert_eq!(x, dex);
    s2.commit();
    assert_eq!(tag, s2.squeeze_n(rate));

    let mut x2 = x.clone();
    s3.encrypt_inplace(&mut x2);
    assert_eq!(ex, x2);
    s3.commit();
    assert_eq!(tag, s3.squeeze_n(rate));

    s4.decrypt_inplace(&mut x2);
    assert_eq!(x, x2);
    s4.commit();
    assert_eq!(tag, s4.squeeze_n(rate));
}
