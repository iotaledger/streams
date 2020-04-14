#[macro_use]
extern crate criterion;

use criterion::{
    Benchmark,
    Criterion,
};
use iota_streams_core::{
    prng,
    tbits::{
        trinary::Trit,
        Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use std::{
    str::FromStr,
    time::Duration,
};

const MT_HEIGHT: usize = 2;

fn mss_benchmark<P>(c: &mut Criterion, name: &str)
where
    P: 'static + mss::Parameters<Trit>,
{
    let duration_ms = 1000;

    let prng = prng::dbg_init_str::<Trit, P::PrngG>("PRNGK");
    let nonce = Tbits::<Trit>::from_str("NONCE").unwrap();
    let sk = mss::PrivateKey::<Trit, P>::gen(&prng, nonce.slice(), MT_HEIGHT);
    let pk = sk.public_key().clone();
    let hash = prng.gen_tbits(&nonce, P::HASH_SIZE);
    let hash2 = hash.clone();
    let sig = sk.sign_tbits(&hash);

    c.bench(
        format!("Run MSS Traversal (h={}) {}", MT_HEIGHT, name).as_str(),
        Benchmark::new("gen", move |b| {
            b.iter(|| {
                mss::PrivateKey::<Trit, P>::gen(&prng, nonce.slice(), MT_HEIGHT);
            })
        })
        .with_function("sign", move |b| {
            b.iter(|| {
                let sig = sk.sign_tbits(&hash);
            })
        })
        .with_function("verify", move |b| {
            b.iter(|| {
                let vfy = pk.verify_tbits(&hash2, &sig);
            })
        })
        .sample_size(10)
        .measurement_time(Duration::from_millis(duration_ms)),
    );
}

fn mss_keccakt_benchmark(c: &mut Criterion) {
    mss_benchmark::<mss::keccak::ParametersMtTraversalT<Trit>>(c, "KeccakF1600T");
    mss_benchmark::<mss::keccak::ParametersMtCompleteT<Trit>>(c, "KeccakF1600T");
}

criterion_group!(benches, mss_keccakt_benchmark);
criterion_main!(benches);
