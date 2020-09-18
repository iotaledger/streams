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
        message,
    },
    core::{
        print,
        println,
    },
    ddml::types::*,
};

use anyhow::{
    ensure,
    Result,
};

use super::utils;

pub fn example<T: Transport>(
    transport: &mut T,
    send_opt: T::SendOptions,
    recv_opt: T::RecvOptions,
    multi_branching: bool,
    seed: &str,
) -> Result<()>
where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
{
    let multi_branching_flag = 0_u8;
    let encoding = "utf-8";
    let mut author = Author::new(seed, encoding, PAYLOAD_BYTES, multi_branching_flag == 1_u8);
    println!("  Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES);
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", encoding, PAYLOAD_BYTES);
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", encoding, PAYLOAD_BYTES);

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.announce()?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        print!("  Author     : {}", author);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    {
        let msg = transport.recv_message_with_options(&announcement_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::ANNOUNCE),
            "Message is not an announcement"
        );

        subscriberA.unwrap_announcement(preparsed.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(
            (author.channel_address() == subscriberA.channel_address()),
            "SubscriberA channel address does not match Author channel address"
        );
        subscriberB.unwrap_announcement(preparsed.clone())?;
        print!("  SubscriberB: {}", subscriberB);
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "SubscriberB channel address does not match Author channel address"
        );
        subscriberC.unwrap_announcement(preparsed)?;
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
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Subscribe A");
    {
        let msg = transport.recv_message_with_options(&subscribeA_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::SUBSCRIBE),
            "Wrong message type: {}",
            preparsed.header.content_type
        );
        author.unwrap_subscribe(preparsed)?;
        print!("  Author     : {}", author);
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        print!("  SubscriberB: {}", subscriberB);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Subscribe B");
    {
        let msg = transport.recv_message_with_options(&subscribeB_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::SUBSCRIBE),
            "Wrong message type: {}",
            preparsed.header.content_type
        );
        author.unwrap_subscribe(preparsed)?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let previous_msg_link = {
        let (msg, seq) = author.share_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Keyload");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::KEYLOAD),
            "Wrong message type: {}",
            preparsed.header.content_type
        );

        let resultC = subscriberC.unwrap_keyload(preparsed.clone());
        print!("  SubscriberC: {}", subscriberC);
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");

        subscriberA.unwrap_keyload(preparsed.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.unwrap_keyload(preparsed)?;
        print!("  SubscriberB: {}", subscriberB);
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        print!("  Author     : {}", author);
        let (msg, seq) = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Signed packet");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::SIGNED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA, transport, recv_opt, multi_branching);

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Tagged packet 1");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::TAGGED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed.clone())?;
        print!("  Author     : {}", author);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
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
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Tagged packet 2");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::TAGGED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );
    }

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Tagged packet 3");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::TAGGED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );
    }

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB, transport, recv_opt, multi_branching);

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let (msg, seq) = subscriberB.tag_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberB: {}", subscriberB);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Tagged packet 4");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::TAGGED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_tagged_packet(preparsed.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
        print!("  SubscriberC: {}", subscriberC);
        ensure!(
            resultC.is_err(),
            "Subscriber C should not be able to access this message"
        );
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author, transport, recv_opt, multi_branching);

    println!("\nSigned packet");
    let previous_msg_link = {
        let (msg, seq) = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.link.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    println!("\nHandle Signed packet");
    {
        let msg = transport.recv_message_with_options(&previous_msg_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(
            preparsed.check_content_type(message::SIGNED_PACKET),
            "Wrong message type: {}",
            preparsed.header.content_type
        );

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed.clone())?;
        print!("  SubscriberA: {}", subscriberA);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberB.unwrap_signed_packet(preparsed)?;
        print!("  SubscriberB: {}", subscriberB);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    Ok(())
}
