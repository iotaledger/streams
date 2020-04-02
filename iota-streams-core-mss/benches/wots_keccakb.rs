#[macro_use]
extern crate criterion;

use criterion::{Benchmark, Criterion};
use iota_streams_core::prng;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core::tbits::{binary::Byte, Tbits};
use iota_streams_core_mss::signature::wots;
use std::str::FromStr;
use std::time::Duration;
use wots::Parameters as _;

fn wots_benchmark<P, G>(c: &mut Criterion, name: &str)
where
    P: 'static + wots::Parameters<Byte>,
    G: 'static + PRP<Byte> + Clone + Default,
{
    let duration_ms = 1000;

    {
        let prng = prng::dbg_init_str::<Byte, G>("DEADBEEF");
        let nonce = Tbits::<Byte>::from_str("FEEDFACE").unwrap();
        let sk = wots::PrivateKey::<Byte, P>::gen(&prng, &[nonce.slice()]);
        let pk = wots::PublicKey::<Byte, P>::gen(&sk);
        let hash = prng.gen_tbits(&nonce, P::HASH_SIZE);
        let hash2 = hash.clone();
        let sig = sk.sign_tbits(&hash);

        c.bench(
            format!("Run WOTS {}", name).as_str(),
            Benchmark::new("gen", move |b| {
                b.iter(|| {
                    wots::PrivateKey::<Byte, P>::gen::<G>(&prng, &[nonce.slice()]);
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
}

fn wots_keccakb_benchmark(c: &mut Criterion) {
    use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600B;
    wots_benchmark::<wots::keccak::ParametersB<Byte>, KeccakF1600B>(c, "KeccakF1600B");
}

criterion_group!(benches, wots_keccakb_benchmark);
criterion_main!(benches);
