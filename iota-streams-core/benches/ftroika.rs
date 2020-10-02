#[macro_use]
extern crate criterion;

use criterion::Criterion;
use iota_streams_core::sponge::prp::troika::TroikaSponge;

fn basic_ftroika() {
    let mut ftroika = TroikaSponge::default();
    let mut input = [0u8; 8019];
    let mut output = [0u8; 243];

    // let mut rng = thread_rng();
    // for trit in input.iter_mut() {
    // trit = rng.gen_range(0, 3);
    // }

    // ftroika.permutation();
    ftroika.absorb(&input);
    ftroika.finalize();
    ftroika.squeeze(&mut output);
}

fn ftroika_benchmark(c: &mut Criterion) {
    c.bench_function("Ftroika with input of 8019 trits", |b| b.iter(|| basic_ftroika()));
}

criterion_group!(benches, ftroika_benchmark);
criterion_main!(benches);
