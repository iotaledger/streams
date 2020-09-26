use iota_streams::{
    app::{
        message::HasLink,
        transport::tangle::PAYLOAD_BYTES,
    },
    app_channels::{
        api::tangle::{
            Author,
            Subscriber,
            Transport,
        },
    },
    core::{
        prelude::Rc,
        print,
        println,
    },
    ddml::types::*,
};

use std::cell::RefCell;

use anyhow::{
    ensure,
    Result,
};

use super::utils;

pub fn example<T: Transport>(
    transport: Rc<RefCell<T>>,
    send_opt: T::SendOptions,
    recv_opt: T::RecvOptions,
    multi_branching: bool,
    seed: &str,
) -> Result<()>
where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    let encoding = "utf-8";
    let mut author = Author::new(seed, encoding, PAYLOAD_BYTES, multi_branching, transport.clone(), recv_opt, send_opt);
    println!("  Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES, transport.clone(), recv_opt, send_opt);
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", encoding, PAYLOAD_BYTES, transport.clone(), recv_opt, send_opt);
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", encoding, PAYLOAD_BYTES, transport.clone(), recv_opt, send_opt);

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.announce()?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        print!("  Author     : {}", author);
        msg.link
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    {
        subscriberA.unwrap_announcement(announcement_link.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(
            (author.channel_address() == subscriberA.channel_address()),
            "SubscriberA channel address does not match Author channel address"
        );
        subscriberB.unwrap_announcement(announcement_link.clone())?;
        print!("  SubscriberB: {}", subscriberB);
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "SubscriberB channel address does not match Author channel address"
        );
        subscriberC.unwrap_announcement(announcement_link.clone())?;
        print!("  SubscriberC: {}", subscriberC);
        ensure!(
            subscriberA.channel_address() == subscriberC.channel_address(),
            "SubscriberC channel address does not match Author channel address"
        );

        ensure!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            "SubscriberA app instance does not match announcement link base"
        );
        ensure!(
            subscriberA.is_multi_branching() == author.is_multi_branching(),
            "Subscribers should have the same branching flag as the author after unwrapping"
        );
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        print!("  SubscriberA: {}", subscriberA);
        msg.link
    };

    println!("\nHandle Subscribe A");
    {
        author.unwrap_subscribe(subscribeA_link)?;
        print!("  Author     : {}", author);
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        print!("  SubscriberB: {}", subscriberB);
        msg.link
    };

    println!("\nHandle Subscribe B");
    {
        author.unwrap_subscribe(subscribeB_link)?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let previous_msg_link = {
        let (msg, seq) = author.share_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        msg.link
    };

    println!("\nHandle Keyload");
    {
        let resultC = subscriberC.unwrap_keyload(previous_msg_link.clone());
        print!("  SubscriberC: {}", subscriberC);
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");

        subscriberA.unwrap_keyload(previous_msg_link.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.unwrap_keyload(previous_msg_link.clone())?;
        print!("  SubscriberB: {}", subscriberB);
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        print!("  Author     : {}", author);
        let (msg, seq) = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        msg.link
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(previous_msg_link.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA);

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg.link
    };

    println!("\nHandle Tagged packet 1");
    {
        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(previous_msg_link.clone())?;
        print!("  Author     : {}", author);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(previous_msg_link.clone());
        print!("  SubscriberC: {}", subscriberC);
        ensure!(
            resultC.is_err(),
            "Subscriber C should not be able to access this message"
        );
    }

    println!("\nTagged packet 2 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg.link
    };

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg.link
    };

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB);

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let (msg, seq) = subscriberB.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberB: {}", subscriberB);
        msg.link
    };

    println!("\nHandle Tagged packet 4");
    {
        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_tagged_packet(previous_msg_link.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(previous_msg_link.clone());
        print!("  SubscriberC: {}", subscriberC);
        ensure!(
            resultC.is_err(),
            "Subscriber C should not be able to access this message"
        );
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author);

    println!("\nSigned packet");
    let previous_msg_link = {
        let (msg, seq) = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        msg.link
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(previous_msg_link.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberB.unwrap_signed_packet(previous_msg_link)?;
        print!("  SubscriberB: {}", subscriberB);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    Ok(())
}
