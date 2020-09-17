#![allow(non_snake_case)]
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

fn run_main<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions) -> Result<()>
where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    // let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    // let seed1: &str = &(0..10)
    // .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
    // .collect::<String>();
    // let seed2: &str = &(0..10)
    // .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
    // .collect::<String>();
    let seed1: &str = "SEEDSINGLE";
    let seed2: &str = "SEEDMULTI9";

    println!("Running Single Branch Test, seed: {}", seed1);
    let result = branching::single_branch::example(transport, send_opt, recv_opt, false, seed1);
    if result.is_err() {
        println!("Error in Single Branch test: {:?}", result.err());
        println!("#######################################\n");
    } else {
        println!("Single Branch Test completed!!");
        println!("#######################################\n");
    }

    // println!("Running Multi Branch Test, seed: {}", seed2);
    // let result = branching::multi_branch::example(transport, send_opt, recv_opt, true, &seed2);
    // if result.is_err() {
    // println!("Error in Multi Branch test: {:?}", result.err());
    // println!("#######################################\n");
    // } else {
    // println!("Multi Branch Test completed!!");
    // println!("#######################################\n");
    // }

    Ok(())
}

#[allow(dead_code)]
fn main_pure() -> Result<()> {
    let mut transport = iota_streams::app_channels::api::tangle::BucketTransport::new();
    run_main(&mut transport, (), ())
}

#[allow(dead_code)]
fn main_client() -> Result<()> {
    let mut client = iota_client::Client::get();
    iota_client::Client::add_node("http://localhost:14265").unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 14;
    let recv_opt = RecvOptions { flags: 0 };

    run_main(&mut client, send_opt, recv_opt)
}

fn main() {
    assert!(main_pure().is_ok());
    // assert!(main_client().is_ok());
}
