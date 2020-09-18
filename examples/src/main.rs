#![allow(non_snake_case)]
#![allow(dead_code)]
//#![no_std]

use anyhow::Result;
use iota::client as iota_client;
use rand::Rng;

use iota_streams::{
    app::transport::tangle::client::{
        RecvOptions,
        SendTrytesOptions,
    },
    app_channels::api::tangle::Transport,
    core::prelude::String,
};

mod branching;

fn run_single_branch_test<T: Transport>(
    transport: &mut T,
    send_opt: T::SendOptions,
    recv_opt: T::RecvOptions,
    seed: &str,
) where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    println!("Running Single Branch Test, seed: {}", seed);
    match branching::single_branch::example(transport, send_opt, recv_opt, false, seed) {
        Err(err) => println!("Error in Single Branch test: {:?}", err),
        Ok(_) => println!("Single Branch Test completed!!"),
    }
    println!("#######################################\n");
}

fn run_multi_branch_test<T: Transport>(
    transport: &mut T,
    send_opt: T::SendOptions,
    recv_opt: T::RecvOptions,
    seed: &str,
) where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    println!("Running Multi Branch Test, seed: {}", seed);
    match branching::multi_branch::example(transport, send_opt, recv_opt, true, seed) {
        Err(err) => println!("Error in Multi Branch test: {:?}", err),
        Ok(_) => println!("Multi Branch Test completed!!"),
    }
    println!("#######################################\n");
}

fn run_main<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions) -> Result<()>
where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    let seed1: &str = "SEEDSINGLE";
    let seed2: &str = "SEEDMULTI9";

    run_single_branch_test(transport, send_opt, recv_opt, seed1);
    run_multi_branch_test(transport, send_opt, recv_opt, seed2);

    Ok(())
}

#[allow(dead_code)]
fn main_pure() {
    let mut transport = iota_streams::app_channels::api::tangle::BucketTransport::new();

    println!("#######################################");
    println!("Running pure tests without accessing Tangle");
    println!("#######################################");
    println!("\n");
    run_single_branch_test(&mut transport, (), (), "PURESEEDA");
    run_multi_branch_test(&mut transport, (), (), "PURESEEDB");
}

#[allow(dead_code)]
fn main_client() {
    let mut client = iota_client::Client::get();
    let node = "http://localhost:14265"; //"https://nodes.devnet.iota.org:443";
    iota_client::Client::add_node(node).unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 14;
    let recv_opt = RecvOptions { flags: 0 };

    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    let seed1: &str = &(0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect::<String>();
    let seed2: &str = &(0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect::<String>();

    println!("#######################################");
    println!("Running tests accessing Tangle via node {}", node);
    println!("#######################################");
    println!("\n");
    run_single_branch_test(&mut client, send_opt, recv_opt, seed1);
    run_multi_branch_test(&mut client, send_opt, recv_opt, seed2);
}

fn main() {
    main_pure();
    // main_client();
}
