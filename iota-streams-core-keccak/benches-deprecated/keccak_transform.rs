#[macro_use]
extern crate criterion;

use criterion::Criterion;
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600B;

fn keccakf1600_benchmark(c: &mut Criterion) {
    let mut keccak = KeccakF1600B::default();
    c.bench_function("Run KeccakF1600 transform", move |b| {
        b.iter(|| {
            keccak.permutation();
        })
    });
}

criterion_group!(benches, keccakf1600_benchmark);
criterion_main!(benches);
