use iota_streams::{
    app::transport::tangle::PAYLOAD_BYTES,
    app_channels::api::tangle::{
        Author,
        Subscriber,
        Transport,
    },
    core::{
        panic_if_not,
        prelude::Rc,
        println,
        Result,
    },
    ddml::types::*,
};

use core::cell::RefCell;

use super::utils;
use std::thread::sleep;
use std::time::Duration;

pub fn example<T: Transport>(transport: Rc<RefCell<T>>, multi_branching: bool, seed: &str) -> Result<()> {
    let encoding = "utf-8";
    let mut author = Author::new(seed, encoding, PAYLOAD_BYTES, multi_branching, transport.clone());
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES, transport.clone());

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce()?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    subscriberA.receive_announcement(&announcement_link)?;

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        msg
    };

    println!("\nHandle Subscribe A");
    author.receive_subscribe(&subscribeA_link)?;

    println!("\nShare keyload");
    let mut previous_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        msg
    };

    for i in 1..6 {
        println!("Signed packet {} - Author", i);
        previous_msg_link = {
            let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
            println!("  msg => <{}> {}", msg.msgid, msg);
            panic_if_not(seq.is_none());
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Subscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA);


    for i in 6..11 {
        println!("Tagged packet {} - SubscriberA", i);
        previous_msg_link = {
            let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
            println!("  msg => <{}> {}", msg.msgid, msg);
            panic_if_not(seq.is_none());
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Author fetching transactions...");
    utils::a_fetch_next_messages(&mut author);


    println!("\n\nTime to try to recover the instance...");
    let mut new_author = Author::recover(seed, &announcement_link, multi_branching, transport.clone())?;

    let state = new_author.fetch_state()?;
    let old_state = author.fetch_state()?;

    let mut latest_link = &announcement_link;

    for (pk, cursor) in state.iter() {
        let mut exists = false;
        for (p, c) in old_state.iter() {
            if pk == p {
                if cursor.link == c.link &&
                    cursor.branch_no == c.branch_no &&
                    cursor.seq_no == c.seq_no {
                    //Set latest link for sequencing later
                    latest_link = &cursor.link;
                    exists = true
                }
            }
        }
        panic_if_not!(exists);
    }

    println!("States match...\nSending next sequenced message...");
    let (last_msg, _seq) = new_author.send_signed_packet(latest_link, &public_payload, &masked_payload)?;
    println!("  msg => <{}> {}", last_msg.msgid, last_msg);

    //Wait a second for message to propagate
    sleep(Duration::from_secs(1));
    println!("Subscriber A fetching transactions...");
    let msgs = subscriberA.fetch_next_msgs();
    panic_if_not!(!msgs.is_empty());
    panic_if_not!(!(msgs[0].link == last_msg));

    println!("Last message matches, recovery, sync and send successful");


    Ok(())
}
