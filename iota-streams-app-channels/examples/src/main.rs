#![allow(non_snake_case)]
//#![no_std]

use iota::client as iota_client;
use iota_streams_app::transport::tangle::client::RecvOptions;
use rand::Rng;

use iota_streams_app::transport::tangle::client::SendTrytesOptions;

mod branching;

fn main() {
    let mut client = iota_client::Client::get();
    iota_client::Client::add_node("http://localhost:14265").unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 14;
    let recv_opt = RecvOptions{ flags: 0 };

    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    let seed1: String = (0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect();
    let seed2: String = (0..10)
        .map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect();

    println!("Running Single Branch Test, seed: {}", seed1);
    let result = branching::single_branch::example(&mut client, send_opt, recv_opt, false, &seed1);
    if result.is_err() {
        println!("Error in Single Branch test: {:?}", result.err());
        println!("#######################################\n");
    } else {
        println!("Single Branch Test completed!!");
        println!("#######################################\n");
    }

    println!("Running Multi Branch Test, seed: {}", seed2);
    let result = branching::multi_branch::example(&mut client, send_opt, recv_opt, true, &seed2);
    if result.is_err() {
        println!("Error in Multi Branch test: {:?}", result.err());
        println!("#######################################\n");
    } else {
        println!("Multi Branch Test completed!!");
        println!("#######################################\n");
    }
}
