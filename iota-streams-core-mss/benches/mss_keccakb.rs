#[macro_use]
extern crate criterion;

use criterion::{Benchmark, Criterion};
use iota_streams_core::prng;
use iota_streams_core::tbits::{binary::Byte, Tbits};
use iota_streams_core_mss::signature::mss;
use std::str::FromStr;
use std::time::Duration;

const MT_HEIGHT: usize = 2;

fn mss_benchmark<P>(c: &mut Criterion, name: &str)
where
    P: 'static + mss::Parameters<Byte>,
{
    let duration_ms = 1000;

    let prng = prng::dbg_init_str::<Byte, P::PrngG>("DEADBEEF");
    let nonce = Tbits::<Byte>::from_str("FEEDFACE").unwrap();
    let sk = mss::PrivateKey::<Byte, P>::gen(&prng, nonce.slice(), MT_HEIGHT);
    let pk = sk.public_key().clone();
    let hash = prng.gen_tbits(&nonce, P::HASH_SIZE);
    let hash2 = hash.clone();
    let sig = sk.sign_tbits(&hash);

    c.bench(
        format!("Run MSS Traversal (h={}) {}", MT_HEIGHT, name).as_str(),
        Benchmark::new("gen", move |b| {
            b.iter(|| {
                mss::PrivateKey::<Byte, P>::gen(&prng, nonce.slice(), MT_HEIGHT);
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

fn mss_keccakb_benchmark(c: &mut Criterion) {
    mss_benchmark::<mss::keccak::ParametersMtTraversalB<Byte>>(c, "KeccakF1600B");
    mss_benchmark::<mss::keccak::ParametersMtCompleteB<Byte>>(c, "KeccakF1600B");
}

criterion_group!(benches, mss_keccakb_benchmark);
criterion_main!(benches);
