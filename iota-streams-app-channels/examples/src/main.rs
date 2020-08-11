#![allow(non_snake_case)]
//#![no_std]

use iota_streams_app_channels::{
    api::tangle::{
        Address,
        Author,
        BucketTransport,
        Subscriber,
        Transport,
    },
    message,
};

use rand::Rng;
use iota::client as iota_client;

use anyhow::{
    ensure,
    Result,
};

use iota_streams_app::{
    transport::tangle::client::SendTrytesOptions,
    message::HasLink
};

use iota_streams_protobuf3::types::*;
//use std::str::FromStr;
use heapless::String;
use heapless::Vec;
use heapless::consts::U256;
use hex;
use std::string::String as stdString;


fn example<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions, seed: &str) -> Result<()>
    where
        T::SendOptions: Copy,
        T::RecvOptions: Copy,
{
    let mut author = Author::new(seed);

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED");
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED");
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED");

    println!("SubA pk: {:?}", subscriberA.sub_sig_public_key().to_bytes());
    println!("SubB pk: {:?}", subscriberB.sub_sig_public_key().to_bytes());
    println!("SubC pk: {:?}", subscriberC.sub_sig_public_key().to_bytes());


    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let (announcement_address, announcement_tag) = {
        let msg = &author.announce().unwrap();
        transport.send_message_with_options(&msg, send_opt);
        (msg.link.appinst.tbits().clone(), msg.link.msgid.tbits().clone())
    };

    let mut v1 = Vec::<u8, U256>::new();
    v1.extend_from_slice(&announcement_address);

    let mut v2 = Vec::<u8, U256>::new();
    v2.extend_from_slice(&announcement_tag);

    let announcement_link = Address::from_str(&hex::encode(announcement_address), &hex::encode(announcement_tag)).unwrap();
    println!("Announcement link at: {}", &announcement_link);
    {
        let msg = transport.recv_message_with_options(&announcement_link, recv_opt).unwrap();
        let preparsed = msg.parse_header().unwrap();
        ensure!(preparsed.check_content_type(&message::announce::TYPE), "Message is not an announcement");

        subscriberA.unwrap_announcement(preparsed.clone()).unwrap();
        ensure!((author.channel_address() == subscriberA.channel_address().unwrap()),
            "SubscriberA channel address does not match Author channel address");
        subscriberB.unwrap_announcement(preparsed).unwrap();
        ensure!(subscriberA.channel_address() == subscriberB.channel_address(),
            "SubscriberB channel address does not match Author channel address");
        ensure!(subscriberA
            .channel_address()
            .map_or(false, |appinst| appinst == announcement_link.base()),
                    "SubscriberA app instance does not match announcement link base");
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.subscribe(&announcement_link)?;
        transport.send_message_with_options(&msg, send_opt)?;
        println!("Subscribe at {}", msg.link.msgid);
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&subscribeA_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::subscribe::TYPE), "Wrong message type: {}", preparsed.header.content_type);
        author.unwrap_subscribe(preparsed)?;
    }

    println!("\nShare keyload for everyone [SubscriberA]");
    let keyload_link = {
        let msg = author.share_keyload_for_everyone(&announcement_link).unwrap();
        transport.send_message_with_options(&msg, send_opt);
        println!("Keyload message at {}", &msg.link.msgid);
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&keyload_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::keyload::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let resultB = subscriberB.unwrap_keyload(preparsed.clone());
        ensure!(resultB.is_err(), "SubscriberB should not be able to unwrap the keyload");
        let resultC = subscriberC.unwrap_keyload(preparsed.clone());
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");
        subscriberA.unwrap_keyload(preparsed)?;

    }


    println!("\nSigned packet");
    let signed_packet_link = {
        let msg = author.sign_packet(&keyload_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg, send_opt);
        println!("Signed packet at {}", &msg.link.msgid);
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&signed_packet_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::signed_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        transport.send_message_with_options(&msg, send_opt)?;
        println!("Subscribe at {}", msg.link.msgid);
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&subscribeB_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::subscribe::TYPE), "Wrong message type: {}", preparsed.header.content_type);
        author.unwrap_subscribe(preparsed)?;
    }


    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let keyload_link = {
        let msg = author.share_keyload_for_everyone(&signed_packet_link).unwrap();
        transport.send_message_with_options(&msg, send_opt);
        println!("Keyload message at {}", &msg.link.msgid);
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&keyload_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::keyload::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let resultC = subscriberC.unwrap_keyload(preparsed.clone());
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");
        subscriberA.unwrap_keyload(preparsed.clone())?;
        subscriberB.unwrap_keyload(preparsed)?;

    }

    println!("\nTagged packet - SubscriberA");
    let tagged_packet_link = {
        let msg = subscriberA.tag_packet(&keyload_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg, send_opt);
        println!("Tagged packet at {}", &msg.link.msgid);
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&tagged_packet_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nTagged packet - SubscriberB");
    let tagged_packet_link = {
        let msg = subscriberB.tag_packet(&keyload_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg, send_opt);
        println!("Tagged packet at {}", &msg.link.msgid);
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&tagged_packet_link, recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    Ok(())
}

fn main() {
    let mut client = iota_client::ClientBuilder::new()
        .node("http://192.168.1.68:14265")
        .unwrap()
        .build()
        .unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 3;
    let recv_opt = ();

    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    let seed1: stdString = (0..10).map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0,27)).unwrap()).collect();

    println!("Running Test, seed: {}", seed1);
    example(&mut client, send_opt, recv_opt, &seed1);
    println!("Test completed!!")
}
