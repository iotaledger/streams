#[macro_use]
extern crate criterion;

use criterion::{Benchmark, Criterion};
use iota_streams_core::sponge::spongos::Spongos;
use iota_streams_core::tbits::{binary::Byte, Tbits};
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600B;
use std::time::Duration;

fn step(key: &Tbits<Byte>, x: &Tbits<Byte>) {
    const MAC_SIZE: usize = Spongos::<Byte, KeccakF1600B>::MAC_SIZE;
    let mut s = Spongos::<Byte, KeccakF1600B>::init();
    s.absorb_tbits(key);
    s.absorb_tbits(x);
    s.commit();
    s.encrypt_tbits(x);
    s.commit();
    s.squeeze_tbits(MAC_SIZE);
}

fn keccakf1600b_benchmark(c: &mut Criterion) {
    const KEY_SIZE: usize = Spongos::<Byte, KeccakF1600B>::KEY_SIZE;

    {
        let key = Tbits::<Byte>::zero(KEY_SIZE);
        let x1B = Tbits::<Byte>::zero(1);
        c.bench_function("Run KeccakF1600B spongos/(1B)", move |b| {
            b.iter(|| step(&key, &x1B))
        });
    }

    {
        let key = Tbits::<Byte>::zero(KEY_SIZE);
        let x1KiB = Tbits::<Byte>::zero(1024);
        c.bench_function("Run KeccakF1600B spongos/(1KiB)", move |b| {
            b.iter(|| {
                step(&key, &x1KiB);
            })
        });
    }

    {
        let key = Tbits::<Byte>::zero(KEY_SIZE);
        let x1MiB = Tbits::<Byte>::zero(1024 * 1024);
        c.bench(
            "Run KeccakF1600B spongos",
            Benchmark::new("(1MiB)", move |b| {
                b.iter(|| {
                    step(&key, &x1MiB);
                })
            })
            .sample_size(10)
            .measurement_time(Duration::from_millis(10000)),
        );
    }
}

criterion_group!(benches, keccakf1600b_benchmark);
criterion_main!(benches);
