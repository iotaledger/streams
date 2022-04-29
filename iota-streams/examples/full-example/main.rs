// Rust
use std::{
    cell::RefCell,
    env,
    rc::Rc,
};

// 3rd-party
use anyhow::Result;
use rand::Rng;

// IOTA

// Streams
use iota_streams::{
    transport::{
        bucket,
        tangle,
        Transport,
    },
    Address,
    Message,
};
use LETS::message::TransportMessage;

mod branching;

trait GenericTransport:
    for<'a> Transport<&'a Address, TransportMessage<Vec<u8>>, TransportMessage<Vec<u8>>> + Clone
{
}

impl<T> GenericTransport for T where
    T: for<'a> Transport<&'a Address, TransportMessage<Vec<u8>>, TransportMessage<Vec<u8>>> + Clone
{
}

// async fn run_recovery_test<T: GenericTransport>(transport: T, seed: &str) {
//     println!("\tRunning Recovery Test, seed: {}", seed);
//     match branching::recovery::example(transport, seed).await {
//         Err(err) => println!("Error in recovery test: {:?}", err),
//         Ok(_) => println!("\tRecovery test completed!!"),
//     }
//     println!("#######################################");
// }

// async fn run_did_author_test(transport: tangle::Client) {
//     println!("\tRunning DID Test");
//     match branching::did_author::example(transport).await {
//         Err(err) => println!("Error in DID test: {:?}", err),
//         Ok(_) => println!("\tDID test completed!!"),
//     }
//     println!("#######################################");
// }

async fn run_multi_branch_test<T: GenericTransport>(transport: T, seed: &str) -> Result<()> {
    println!("Running multi branch test with seed: {}", seed);
    let result = branching::multi_branch::example(transport, seed).await;
    match &result {
        Err(err) => println!("Error in Multi Branch test: {:?}", err),
        Ok(_) => println!("Multi Branch Test completed successfully!!"),
    };
    println!("#######################################");
    result
}

async fn main_pure() -> Result<()> {
    let transport = bucket::Client::new();

    println!("\n");
    println!("###########################################");
    println!("Running pure tests without accessing Tangle");
    println!("###########################################");
    println!("\n");

    // BucketTransport is an in-memory storage that needs to be shared between all the users,
    // hence the Rc<RefCell<BucketTransport>>
    let transport = Rc::new(RefCell::new(transport));

    run_multi_branch_test(transport.clone(), "PURESEEDA").await?;
    // run_recovery_test(transport, "PURESEEDB").await;
    println!("Done running pure tests without accessing Tangle");
    println!("################################################");
    Ok(())
}

async fn main_client() -> Result<()> {
    // Parse env vars with a fallback
    let node_url = env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    let transport = Rc::new(RefCell::new(
        tangle::Client::for_node(&node_url)
            .await
            .expect(&format!("error connecting Tangle client to '{}'", node_url)),
    ));

    println!("#######################################");
    println!("Running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
    println!("\n");

    run_multi_branch_test(transport.clone(), &new_seed()).await?;
    // run_recovery_test(transport.clone(), &new_seed()).await;
    // run_did_author_test(transport).await;
    println!("Done running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
    Ok(())
}

fn new_seed() -> String {
    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    (0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0..27)).unwrap())
        .collect::<String>()
}

#[tokio::main]
async fn main() -> Result<()> {
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
