#[macro_use]
extern crate criterion;

use criterion::{
    Benchmark,
    Criterion,
};
use iota_streams_core::{
    prng,
    sponge::prp::{
        troika::Troika,
        PRP,
    },
    tbits::{
        trinary::Trit,
        Tbits,
    },
};
use iota_streams_core_mss::signature::wots;
use std::{
    str::FromStr,
    time::Duration,
};
use wots::Parameters as _;

fn wots_benchmark<P, G>(c: &mut Criterion, name: &str)
where
    P: 'static + wots::Parameters<Trit>,
    G: 'static + PRP<Trit> + Clone + Default,
{
    let duration_ms = 1000;

    {
        let prng = prng::dbg_init_str::<Trit, G>("PRNGK");
        let nonce = Tbits::<Trit>::from_str("NONCE").unwrap();
        let sk = wots::PrivateKey::<Trit, P>::gen(&prng, &[nonce.slice()]);
        let pk = wots::PublicKey::<Trit, P>::gen(&sk);
        let hash = prng.gen_tbits(&nonce, P::HASH_SIZE);
        let hash2 = hash.clone();
        let sig = sk.sign_tbits(&hash);

        c.bench(
            format!("Run WOTS {}", name).as_str(),
            Benchmark::new("gen", move |b| {
                b.iter(|| {
                    wots::PrivateKey::<Trit, P>::gen::<G>(&prng, &[nonce.slice()]);
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

fn wots_troika_benchmark(c: &mut Criterion) {
    use iota_streams_core::sponge::prp::troika::Troika;
    wots_benchmark::<wots::troika::Parameters<Trit>, Troika>(c, "Troika");
}

criterion_group!(benches, wots_troika_benchmark);
criterion_main!(benches);
