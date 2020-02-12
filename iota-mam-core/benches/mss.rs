#[macro_use]
extern crate criterion;
use std::str::FromStr;

use criterion::{Benchmark, Criterion};
use iota_mam_core::{prng, signature::mss::{PrivateKeyMTComplete, PrivateKeyMTTraversal}, trits::Trits};

fn troika_benchmark(c: &mut Criterion) {
    const mt_height: usize = 3;

    c.bench("Run MSS PrivateKey generation",
            Benchmark::new(&format!("MT complete height={})", mt_height), |b| { b.iter(|| {
                let prng = prng::dbg_init_str("BENCHPRNGKEY");
                let nonce = Trits::from_str("BENCHNONCE").unwrap();
                let _sk = PrivateKeyMTComplete::gen(&prng, nonce.slice(), mt_height);
            }) }
            ).with_function(&format!("MT traversal height={})", mt_height), |b| { b.iter(|| {
                let prng = prng::dbg_init_str("BENCHPRNGKEY");
                let nonce = Trits::from_str("BENCHNONCE").unwrap();
                let _sk = PrivateKeyMTTraversal::gen(&prng, nonce.slice(), mt_height);
            }) }
            ).sample_size(10)
    );

    let prng = prng::dbg_init_str("BENCHPRNGKEY");
    let nonce = Trits::from_str("BENCHNONCE").unwrap();
    let sk_complete = PrivateKeyMTComplete::gen(&prng, nonce.slice(), mt_height);
    let sk_traversal = PrivateKeyMTTraversal::gen(&prng, nonce.slice(), mt_height);

    c.bench("Run MSS PrivateKey next",
            Benchmark::new(&format!("MT complete height={})", mt_height), move |b| { b.iter(|| {
                let mut sk = sk_complete.clone();
                while sk.next() {}
            }) }
            ).with_function(&format!("MT traversal height={})", mt_height), move |b| { b.iter(|| {
                let mut sk = sk_traversal.clone();
                while sk.next() {}
            }) }
            ).sample_size(10)
    );
}

criterion_group!(benches, troika_benchmark);
criterion_main!(benches);
