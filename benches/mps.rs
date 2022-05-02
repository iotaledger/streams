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

// const TANGLE_URL: &str = "http://68.183.204.5:14265/";
const TANGLE_URL: &str = "http://65.108.208.75:14265";

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

    let mut group = c.benchmark_group("Transactions per Second [write] [minPoWScore: 200]");
    for n_items_magnitude in 1..=4 {
        let n_items = 1 * n_items_magnitude;
        let mut payload = [0; 1024];
        rand::thread_rng().fill(&mut payload);
        group.throughput(Throughput::Elements(n_items));
        group.sample_size(20);
        // group.sampling_mode(SamplingMode::Flat);
        group.bench_with_input(
            BenchmarkId::new("Streams publisher sendsing signed-packet", n_items),
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
        group.bench_with_input(
            BenchmarkId::new("[baseline] send an indexed payload using iota.rs Client", n_items),
            &(runtime.handle(), n_items),
            |b, &(tokio_handle, n_items)| {
                b.iter(|| {
                    tokio_handle.block_on(async {
                        // let mut payload = payload.to_vec();
                        // let mut hasher = DefaultHasher::new();
                        for i in 0..n_items {
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
    group.finish();
}
criterion_group!(benches, publisher);
criterion_main!(benches);
