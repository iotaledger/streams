use generic_array::{typenum::Unsigned, GenericArray};

use super::{
    prp::{keccak::KeccakF1600, PRP},
    spongos::Spongos,
};

fn bytes_spongosn<F: PRP + Default>(n: usize) {
    let mut rng = Spongos::<F>::init();
    rng.absorb(&vec![0; 10]);
    rng.commit();
    let mut k = vec![0; n];
    let mut p = vec![0; n];
    let mut x = vec![0; n];
    rng.squeeze_mut(&mut k);
    rng.squeeze_mut(&mut p);
    rng.squeeze_mut(&mut x);

    let mut s = Spongos::<F>::init();
    s.absorb(&k);
    s.absorb(&p);
    s.commit();
    let mut y = x.clone();
    s.encrypt_mut(&x, &mut y).unwrap();
    s.commit();
    let mut t = vec![0; n];
    let mut t2 = vec![0; n];
    let mut t3 = vec![0; n];
    s.squeeze_mut(&mut t);
    s.squeeze_mut(&mut t2);
    s.squeeze_mut(&mut t3);

    let mut s = Spongos::<F>::init();
    s.absorb(&k);
    s.absorb(&p);
    s.commit();
    let mut z = y.clone();
    s.decrypt_mut(&y, &mut z).unwrap();
    s.commit();
    let mut u = vec![0; n];
    s.squeeze_mut(&mut u);
    assert!(s.squeeze_eq(&t2));
    assert!(s.squeeze_eq(&t3));

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
}

fn slice_spongosn<F: PRP + Default>(n: usize) {
    let mut k = vec![0u8; n];
    let mut p = vec![0u8; n];
    let mut x = vec![0u8; n];
    let mut y = vec![0u8; n];
    let mut z = vec![0u8; n];
    let mut t = vec![0u8; n];
    let mut u = vec![0u8; n];
    let mut t23 = vec![0u8; n + n];

    let mut s = Spongos::<F>::init();
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
    let mut s = Spongos::<F>::init();
    s.absorb(&vec![1; 32]);
    s.commit();

    let mut x = vec![0; n];
    s.clone().squeeze_mut(&mut x);
    let mut s2 = s.clone();

    let mut ex = x.clone();
    s.encrypt_mut(&x, &mut ex).unwrap();
    s.commit();
    let tag: GenericArray<u8, F::RateSize> = s.squeeze();

    let mut dex = ex.clone();
    s2.decrypt_mut(&ex, &mut dex).unwrap();
    assert_eq!(x, dex);
    s2.commit();
    assert_eq!(tag, s2.squeeze());
}
