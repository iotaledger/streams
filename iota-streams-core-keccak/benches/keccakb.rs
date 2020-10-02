#[macro_use]
extern crate criterion;

use criterion::{
    Benchmark,
    Criterion,
};
use iota_streams_core::sponge::spongos::Spongos;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;
use std::time::Duration;

fn step(key: &[u8], x: &[u8]) {
    const MAC_SIZE: usize = Spongos::<KeccakF1600>::MAC_SIZE;
    let mut s = Spongos::<KeccakF1600>::init();
    s.absorb(key);
    s.absorb(x);
    s.commit();
    // s.encrypt(x);
    s.commit();
    s.squeeze_buf(MAC_SIZE);
}

fn keccakf1600b_benchmark(c: &mut Criterion) {
    const KEY_SIZE: usize = Spongos::<KeccakF1600>::KEY_SIZE;

    {
        let key = vec![0; KEY_SIZE];
        let x1B = vec![1; 1];
        c.bench_function("Run KeccakF1600 spongos/(1B)", move |b| {
            b.iter(|| step(&key[..], &x1B[..]))
        });
    }

    {
        let key = vec![0; KEY_SIZE];
        let x1KiB = vec![1; 1024];
        c.bench_function("Run KeccakF1600 spongos/(1KiB)", move |b| {
            b.iter(|| {
                step(&key[..], &x1KiB[..]);
            })
        });
    }

    {
        let key = vec![0; KEY_SIZE];
        let x1MiB = vec![1; 1024 * 1024];
        c.bench(
            "Run KeccakF1600 spongos",
            Benchmark::new("(1MiB)", move |b| {
                b.iter(|| {
                    step(&key[..], &x1MiB[..]);
                })
            })
            .sample_size(10)
            .measurement_time(Duration::from_millis(10000)),
        );
    }
}

criterion_group!(benches, keccakf1600b_benchmark);
criterion_main!(benches);
