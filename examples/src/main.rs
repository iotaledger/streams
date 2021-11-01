#![allow(non_snake_case)]
#![allow(dead_code)]
//#![no_std]

use std::env;

use rand::Rng;

use iota_streams::{
    app::{
        transport::tangle::client::Client,
        id::create_identity,
    },
    app_channels::api::tangle::{
        ChannelType,
        Transport,
    },
    core::{
        prelude::{
            Rc,
            RefCell,
            String,
        },
        Result,
        iota_identity::iota::Network
    },
};
use iota_streams::core::iota_identity::crypto::KeyPair;
use iota_streams::core::iota_identity::iota::Client as DIDClient;

mod branching;

async fn run_recovery_test<T: Transport>(transport: T, seed: &str) {
    println!("\tRunning Recovery Test, seed: {}", seed);
    match branching::recovery::example(transport, ChannelType::SingleBranch, seed).await {
        Err(err) => println!("Error in recovery test: {:?}", err),
        Ok(_) => println!("\tRecovery test completed!!"),
    }
    println!("#######################################");
}

async fn run_single_branch_test<T: Transport>(transport: T, seed: &str, identity: Option<(String, KeyPair, DIDClient)>) {
    println!("\tRunning Single Branch Test, seed: {}", seed);
    match branching::single_branch::example(identity, transport, ChannelType::SingleBranch, seed).await {
        Err(err) => println!("Error in Single Branch test: {:?}", err),
        Ok(_) => println!("\tSingle Branch Test completed!!"),
    }
    println!("#######################################");
}

async fn run_single_depth_test<T: Transport>(transport: T, seed: &str) {
    println!("\tRunning Single Branch Test, seed: {}", seed);
    match branching::single_depth::example(transport, ChannelType::SingleDepth, seed).await {
        Err(err) => println!("Error in Single Depth test: {:?}", err),
        Ok(_) => println!("\tSingle Depth Test completed!!"),
    }
    println!("#######################################");
}

async fn run_multi_branch_test<T: Transport>(transport: T, seed: &str, identity: Option<(String, KeyPair, DIDClient)>) {
    println!("\tRunning Multi Branch Test, seed: {}", seed);
    match branching::multi_branch::example(identity, transport, ChannelType::MultiBranch, seed).await {
        Err(err) => println!("Error in Multi Branch test: {:?}", err),
        Ok(_) => println!("\tMulti Branch Test completed!!"),
    }
    println!("#######################################");
}


async fn run_main<T: Transport>(transport: T) -> Result<()> {
    let seed1: &str = "SEEDSINGLE";
    let seed2: &str = "SEEDSINGLEDEPTH";
    let seed3: &str = "SEEDMULTI9";
    let seed4: &str = "SEEDRECOVERY";

    run_single_branch_test(transport.clone(), seed1, None).await;
    run_single_depth_test(transport.clone(), seed2).await;
    run_multi_branch_test(transport.clone(), seed3, None).await;
    run_recovery_test(transport, seed4).await;

    Ok(())
}

#[allow(dead_code)]
async fn main_pure() {
    let transport = iota_streams::app_channels::api::tangle::BucketTransport::new();

    println!("#######################################");
    println!("Running pure tests without accessing Tangle");
    println!("#######################################");
    println!("\n");

    // BucketTransport is an in-memory storage that needs to be shared between all the users,
    // hence the Rc<RefCell<BucketTransport>>
    let transport = Rc::new(RefCell::new(transport));

    run_single_branch_test(transport.clone(), "PURESEEDA", None).await;
    run_single_depth_test(transport.clone(), "PURESEEDB").await;
    run_multi_branch_test(transport.clone(), "PURESEEDC", None).await;
    run_recovery_test(transport, "PURESEEDD").await;
    println!("Done running pure tests without accessing Tangle");
    println!("#######################################");
}

#[allow(dead_code)]
async fn main_client() {
    // Parse env vars with a fallback
    let node_url = env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    println!("#######################################");
    println!("Making a DID Account for use in testing at node {}", &node_url);
    println!("#######################################");

    let identity1 = create_identity(&node_url, Network::Mainnet).await.unwrap();
    let identity2 = create_identity(&node_url, Network::Mainnet).await.unwrap();

    let transport = Client::new_from_url(&node_url);

    println!("#######################################");
    println!("Running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
    println!("\n");

    run_single_branch_test(transport.clone(), &new_seed(), Some(identity1)).await;
    run_single_depth_test(transport.clone(), &new_seed()).await;
    run_multi_branch_test(transport.clone(), &new_seed(), Some(identity2)).await;
    run_recovery_test(transport, &new_seed()).await;
    println!("Done running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
}

fn new_seed() -> String {
    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    (0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect::<String>()
}

#[tokio::main]
async fn main() {
    // Load or .env file, log message if we failed
    if dotenv::dotenv().is_err() {
        println!(".env file not found; copy and rename example.env to \".env\"");
    };

    match env::var("TRANSPORT").ok().as_deref() {
        Some("tangle") => main_client().await,
        Some("bucket") | None => main_pure().await,
        Some(other) => panic!("Unexpected TRANSPORT '{}'", other),
    }
}
