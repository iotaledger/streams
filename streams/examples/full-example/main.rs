// Rust
use std::{cell::RefCell, env, rc::Rc};

// 3rd-party
use rand::Rng;

// IOTA

// Streams
use streams::{
    transport::{bucket, Transport},
    Result, TransportMessage,
};

#[cfg(feature = "tangle-client")]
use streams::transport::tangle;

#[cfg(feature = "utangle-client")]
use streams::transport::utangle;

mod scenarios;

// #[derive(Deserialize)]
// struct Ignored {}

// impl TryFrom<Message
trait GenericTransport<SR>: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = SR> + Clone {}

impl<T, SR> GenericTransport<SR> for T where T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = SR> + Clone {}

#[cfg(feature = "did")]
async fn run_did_scenario<SR, T: GenericTransport<SR>>(transport: T) -> Result<()> {
    println!("## Running DID Test ##\n");
    let result = scenarios::did::example(transport).await;
    match &result {
        Err(err) => eprintln!("Error in DID test: {:?}", err),
        Ok(_) => println!("\n## DID test completed successfully!! ##\n"),
    }
    result
}

async fn run_lean_test<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running Lean State Test ##\n");
    let result = scenarios::lean::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in Lean State test: {}", err),
        Ok(_) => println!("\n## Lean State test completed successfully!! ##\n"),
    }
    result
}

async fn run_basic_scenario<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running single branch test with seed: {} ##\n", seed);
    let result = scenarios::basic::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in Single Branch test: {}", err),
        Ok(_) => println!("\n## Single Branch Test completed successfully!! ##\n"),
    };
    result
}

async fn run_filter_branch_test<SR, T: GenericTransport<SR>>(transport: T, seed: &str) -> Result<()> {
    println!("## Running filter test with seed: {} ##\n", seed);
    let result = scenarios::filter::example(transport, seed).await;
    match &result {
        Err(err) => eprintln!("Error in filter test: {}", err),
        Ok(_) => println!("\n## Filter Test completed successfully!! ##\n"),
    };
    result
}

async fn main_pure() -> Result<()> {
    println!("\n");
    println!("###########################################");
    println!("Running pure tests without accessing Tangle");
    println!("###########################################");
    println!("\n");

    let transport = bucket::Client::new();
    // BucketTransport is an in-memory storage that needs to be shared between all the users,
    // hence the Rc<RefCell<BucketTransport>>
    let transport = Rc::new(RefCell::new(transport));

    run_basic_scenario(transport.clone(), "PURESEEDA").await?;
    run_lean_test(transport.clone(), "PURESEEDB").await?;
    run_filter_branch_test(transport.clone(), "PURESEEDC").await?;
    println!("################################################");
    println!("Done running pure tests without accessing Tangle");
    println!("################################################");
    Ok(())
}

#[cfg(feature = "tangle-client")]
async fn main_tangle_client() -> Result<()> {
    // Parse env vars with a fallback
    let node_url = env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    println!("\n");
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("Running tests accessing Tangle with iota.rs via node {}", &node_url);
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("\n");

    let transport: Rc<RefCell<tangle::Client>> =
        Rc::new(RefCell::new(tangle::Client::for_node(&node_url).await.unwrap_or_else(
            |e| panic!("error connecting Tangle client to '{}': {}", node_url, e),
        )));

    run_basic_scenario(transport.clone(), &new_seed()).await?;
    #[cfg(feature = "did")]
    run_did_scenario(transport.clone()).await?;
    run_lean_test(transport.clone(), &new_seed()).await?;
    run_filter_branch_test(transport.clone(), &new_seed()).await?;
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Done running tests accessing Tangle with iota.rs via node {}",
        &node_url
    );
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    Ok(())
}

#[cfg(feature = "utangle-client")]
async fn main_utangle_client() -> Result<()> {
    // Parse env vars with a fallback
    let node_url = env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    println!("\n");
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("Running tests accessing Tangle with uTangle via node {}", &node_url);
    println!(
        "#####################################################{}",
        "#".repeat(node_url.len())
    );
    println!("\n");

    let transport: Rc<RefCell<utangle::Client>> = Rc::new(RefCell::new(utangle::Client::new(&node_url)));

    run_basic_scenario(transport.clone(), &new_seed()).await?;
    #[cfg(feature = "did")]
    run_did_scenario(transport.clone()).await?;
    run_lean_test(transport, &new_seed()).await?;
    println!(
        "##########################################################{}",
        "#".repeat(node_url.len())
    );
    println!(
        "Done running tests accessing Tangle with uTangle via node {}",
        &node_url
    );
    println!(
        "##########################################################{}",
        "#".repeat(node_url.len())
    );
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
        #[cfg(feature = "utangle-client")]
        Some("utangle") => main_utangle_client().await,
        #[cfg(feature = "tangle-client")]
        Some("tangle") => main_tangle_client().await,
        Some("bucket") | None => main_pure().await,
        Some(other) => panic!("Unexpected TRANSPORT '{}'", other),
    }
}
