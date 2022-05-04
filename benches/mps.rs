use std::{
    collections::hash_map::DefaultHasher,
    hash::{
        Hash,
        Hasher,
    },
};

use criterion::{
    criterion_group,
    criterion_main,
    BatchSize,
    BenchmarkId,
    Criterion,
    SamplingMode,
    Throughput,
};
use rand::{
    distributions::Alphanumeric,
    Rng,
};

use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::{
        api::tangle::ChannelType,
        Address,
        Author,
    },
    core_edsig::signature::ed25519::Keypair,
};

fn setup(handle: &tokio::runtime::Handle) -> impl FnMut() -> (Author<Client>, Address) + '_ {
    move || {
        handle.block_on(async {
            let seed: String = rand::thread_rng()
                .sample_iter(Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            let mut author = Author::new(&seed, ChannelType::SingleBranch, Client::new_from_url(TANGLE_URL));
            let announcement = author.send_announce().await.unwrap();
            for _ in 0..100 {
                let kp = Keypair::generate(&mut rand::thread_rng());
                author.store_new_subscriber(kp.public).unwrap();
            }
            let (keyload, _) = author.send_keyload_for_everyone(&announcement).await.unwrap();
            (author, keyload)
        })
    }
}

pub fn publisher(c: &mut Criterion) {
    static KB: usize = 1024;

    // Using the tokio runtime explicitly instead of Bencher::to_async() because setup must also be async
    // (see https://github.com/bheisler/criterion.rs/issues/576).
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut publisher_benchmarks = c.benchmark_group(&format!("Transactions per Second [write] [{}]", TANGLE_URL));
    for n_items_magnitude in 1..=4 {
        let n_items = 1 * n_items_magnitude;
        let mut payload = [0; 1024];
        rand::thread_rng().fill(&mut payload);
        publisher_benchmarks.throughput(Throughput::Elements(n_items));
        publisher_benchmarks.sample_size(30);
        // group.sampling_mode(SamplingMode::Flat);
        publisher_benchmarks.bench_with_input(
            BenchmarkId::new("Streams publisher sending signed-packets", n_items),
            &(runtime.handle(), n_items),
            |b, &(tokio_handle, n_items)| {
                b.iter_batched_ref(
                    setup(runtime.handle()),
                    |(author, keyload)| {
                        // tokio::runtime::Runtime::new().unwrap().block_on(async move {
                        tokio_handle.block_on(async {
                            let (mut last_msg, _) = author
                                .send_signed_packet(keyload, &payload.as_slice().into(), &[].into())
                                .await
                                .unwrap();
                            for _ in 1..n_items {
                                (last_msg, _) = author
                                    .send_signed_packet(&last_msg, &payload.as_slice().into(), &[].into())
                                    .await
                                    .unwrap();
                            }
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let tangle_client = runtime
            .block_on(
                iota_client::Client::builder()
                    .with_node(TANGLE_URL)
                    .unwrap()
                    .with_local_pow(true)
                    .finish(),
            )
            .unwrap();
        publisher_benchmarks.bench_with_input(
            BenchmarkId::new("[baseline] iota.rs Client sending Indexation Payloads", n_items),
            &(runtime.handle(), n_items),
            |b, &(tokio_handle, n_items)| {
                b.iter(|| {
                    tokio_handle.block_on(async {
                        // let mut payload = payload.to_vec();
                        // let mut hasher = DefaultHasher::new();
                        for _ in 0..n_items {
                            // payload.extend(i.to_be_bytes());
                            // payload.hash(&mut hasher);
                            // let index = hasher.finish();
                            tangle_client
                                .message()
                               // .with_index(index.to_be_bytes())
                                .with_index(&payload[0..32])
                                .with_data(payload.to_vec())
                                .finish()
                                .await
                                .unwrap();
                        }
                    });
                });
            },
        );
    }
    publisher_benchmarks.finish();

    let mut subscriber_benchmarks = c.benchmark_group(&format!("Transactions per Second [read] [{}]", TANGLE_URL));
    for n_items_magnitude in 1..=4 {
        let n_items = 1 * n_items_magnitude;
        let mut payload = [0; 1024];
        rand::thread_rng().fill(&mut payload);
        subscriber_benchmarks.throughput(Throughput::Elements(n_items));
        subscriber_benchmarks.sample_size(30);
        // group.sampling_mode(SamplingMode::Flat);
        subscriber_benchmarks.bench_with_input(
            BenchmarkId::new("Streams subscriber reading signed-packets", n_items),
            &(runtime.handle(), n_items),
            |b, &(tokio_handle, n_items)| {
                b.iter_batched_ref(
                    setup(runtime.handle()),
                    |(author, keyload)| {
                        // tokio::runtime::Runtime::new().unwrap().block_on(async move {
                        tokio_handle.block_on(async {
                            let (mut last_msg, _) = author
                                .send_signed_packet(keyload, &payload.as_slice().into(), &[].into())
                                .await
                                .unwrap();
                            for _ in 1..n_items {
                                (last_msg, _) = author
                                    .send_signed_packet(&last_msg, &payload.as_slice().into(), &[].into())
                                    .await
                                    .unwrap();
                            }
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let tangle_client = runtime
            .block_on(
                iota_client::Client::builder()
                    .with_node(TANGLE_URL)
                    .unwrap()
                    .with_local_pow(true)
                    .finish(),
            )
            .unwrap();
        subscriber_benchmarks.bench_with_input(
            BenchmarkId::new("[baseline] iota.rs Client sending Indexation Payloads", n_items),
            &(runtime.handle(), n_items),
            |b, &(tokio_handle, n_items)| {
                b.iter(|| {
                    tokio_handle.block_on(async {
                        // let mut payload = payload.to_vec();
                        // let mut hasher = DefaultHasher::new();
                        for _ in 0..n_items {
                            // payload.extend(i.to_be_bytes());
                            // payload.hash(&mut hasher);
                            // let index = hasher.finish();
                            tangle_client
                                .message()
                               // .with_index(index.to_be_bytes())
                                .with_index(&payload[0..32])
                                .with_data(payload.to_vec())
                                .finish()
                                .await
                                .unwrap();
                        }
                    });
                });
            },
        );
    }
    subscriber_benchmarks.finish();
}
criterion_group!(benches, publisher);
criterion_main!(benches);
