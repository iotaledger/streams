#[macro_use]
extern crate criterion;

use criterion::Criterion;
use iota_mam_core::troika::Troika;

fn troika_benchmark(c: &mut Criterion) {
    let mut troika = Troika::default();
    c.bench_function("Run Troika permutation", move |b| {
        b.iter(|| {
            troika.permutation();
        })
    });
}

criterion_group!(benches, troika_benchmark);
criterion_main!(benches);
