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
use iota_streams_core_edsig::key_exchange::x25519::PublicKeyWrap;
use iota_streams_core::psk::PskIds;


fn example<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions, seed: &str) -> Result<()>
    where
        T::SendOptions: Copy,
        T::RecvOptions: Copy,
{
    let multi_branching_flag = &0_u8;
    let mut author = Author::new(seed, multi_branching_flag == &1_u8);
    println!("Author multi branching?: {:?}", author.get_branching_flag() == &1_u8);

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED");
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED");
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED");

    println!("SubA pubkey: {:?}", subscriberA.sub_ke_public_key().as_bytes());
    println!("SubB pubkey: {:?}", subscriberB.sub_ke_public_key().as_bytes());
    println!("SubC pubkey: {:?}", subscriberC.sub_ke_public_key().as_bytes());

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
        let msg = transport.recv_message_with_options(&announcement_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header().unwrap();
        ensure!(preparsed.check_content_type(&message::announce::TYPE), "Message is not an announcement");

        subscriberA.unwrap_announcement(preparsed.clone()).unwrap();
        ensure!((author.channel_address() == subscriberA.channel_address().unwrap()),
            "SubscriberA channel address does not match Author channel address");
        subscriberB.unwrap_announcement(preparsed.clone()).unwrap();
        ensure!(subscriberA.channel_address() == subscriberB.channel_address(),
            "SubscriberB channel address does not match Author channel address");
        subscriberC.unwrap_announcement(preparsed).unwrap();
        ensure!(subscriberA.channel_address() == subscriberC.channel_address(),
            "SubscriberC channel address does not match Author channel address");

        ensure!(subscriberA
            .channel_address()
            .map_or(false, |appinst| appinst == announcement_link.base()),
                    "SubscriberA app instance does not match announcement link base");
    }

    println!("\nSubscribers unwrapped announcment...");
    println!("SubA multi branching?: {:?}", subscriberA.get_branching_flag() == &1_u8);
    println!("SubB multi branching?: {:?}", subscriberB.get_branching_flag() == &1_u8);
    println!("SubC multi branching?: {:?}", subscriberC.get_branching_flag() == &1_u8);


    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.subscribe(&announcement_link)?;
        transport.send_message_with_options(&msg.0, send_opt)?;
        println!("Subscribe at {}", msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&subscribeA_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::subscribe::TYPE), "Wrong message type: {}", preparsed.header.content_type);
        author.unwrap_subscribe(preparsed)?;
    }


    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        transport.send_message_with_options(&msg.0, send_opt)?;
        println!("Subscribe at {}", msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&subscribeB_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::subscribe::TYPE), "Wrong message type: {}", preparsed.header.content_type);
        author.unwrap_subscribe(preparsed)?;
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let keyload_link = {
        let msg = author.share_keyload_for_everyone(&announcement_link).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Keyload message at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&keyload_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::keyload::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let resultC = subscriberC.unwrap_keyload(preparsed.clone());
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");

        subscriberA.unwrap_keyload(preparsed.clone())?;
        subscriberB.unwrap_keyload(preparsed)?;

    }

    println!("\nSigned packet");
    let signed_packet_link = {
        let msg = author.sign_packet(&keyload_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Signed packet at {}", &msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&signed_packet_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::signed_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("Author fetching transactions...");
    self::a_fetch_next_messages(&mut author, transport, recv_opt, multi_branching_flag.clone());
    println!("Subscriber B fetching transactions...");
    self::s_fetch_next_messages(&mut subscriberB, transport, recv_opt, multi_branching_flag.clone());

    println!("\nTagged packet - SubscriberA");
    let tagged_packet_link = {
        let msg = subscriberA.tag_packet(&signed_packet_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&tagged_packet_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (unwrapped_public, unwrapped_masked) = subscriberB.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
        ensure!(resultC.is_err(), "Subscriber C should not be able to access this message");
    }

    println!("\nTagged packet - SubscriberB");
    let tagged_packet_link = {
        let msg = subscriberB.tag_packet(&keyload_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&tagged_packet_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
        ensure!(resultC.is_err(), "Subscriber C should not be able to access this message");
    }

    println!("Author fetching transactions...");
    self::a_fetch_next_messages(&mut author, transport, recv_opt, multi_branching_flag.clone());

    println!("\nSigned packet");
    let signed_packet_link = {
        let msg = author.sign_packet(&tagged_packet_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Signed packet at {}", &msg.0.link.msgid);
        msg.0.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&signed_packet_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::signed_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (unwrapped_public, unwrapped_masked) = subscriberB.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    Ok(())
}


fn s_fetch_next_messages<T: Transport>(subscriber: &mut Subscriber, transport: &mut T, recv_opt: T::RecvOptions, multi_branching_flag: u8)
    where
        T::RecvOptions: Copy,
{
    let mut next_id: Address;
    let mut seq_num: usize;

    let mut exists = true;
    let mut retry = false;

    while exists {
        println!("Subscriber Looking for next sequenced message...");
        let ids = subscriber.gen_next_msg_ids(multi_branching_flag == 1_u8, retry.clone());
        exists = false;

        for id in ids.iter() {
            next_id = id.1.clone();
            seq_num = id.2.clone();

            let msg = transport.recv_message_with_options(&next_id, multi_branching_flag.clone(), recv_opt).ok();
            if msg.is_none() {
                continue
            }

            let mut unwrapped = msg.unwrap();

            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                let content_type = stdString::from_utf8(preparsed.header.content_type.0[..].to_vec()).unwrap();
                println!("\nMessage exists at {} with {}", &preparsed.header.link.rel(), &content_type);
                match content_type.as_str() {
                    message::signed_packet::TYPE => {
                        let _unwrapped = subscriber.unwrap_signed_packet(preparsed.clone());
                        println!("Found a signed packet");
                        break
                    },
                    message::tagged_packet::TYPE => {
                        let _unwrapped = subscriber.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break
                    },
                    message::keyload::TYPE => {
                        let _unwrapped = subscriber.unwrap_keyload(preparsed.clone());
                        println!("Found a keyload packet");
                        break
                    },
                    message::sequence::TYPE => {
                        println!("Found sequenced message...");
                        let msgid = subscriber.unwrap_sequence(preparsed.clone()).unwrap();
                        let msg = transport.recv_message_with_options(&msgid, multi_branching_flag.clone(), recv_opt).ok();
                        subscriber.store_state(id.0.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    },
                    _ => {
                        println!("Not a recognised type... {}", preparsed.content_type().as_str());
                        break
                    }
                }
            }

            if !(multi_branching_flag == 1_u8) {
                subscriber.store_state_for_all(next_id.clone(), seq_num);
            }
            retry = false;
            exists = true;
        }

        if !exists {
            if !&retry {
                exists = true;
                retry = true;
                continue;
            }
            println!("No more messages in sequence.\n");
        }
    }
}

fn a_fetch_next_messages<T: Transport>(author: &mut Author, transport: &mut T, recv_opt: T::RecvOptions, multi_branching_flag: u8)
    where
        T::RecvOptions: Copy,
{
    let mut next_id: Address;
    let mut seq_num: usize;

    let mut exists = true;
    let mut retry = false;

    while exists {
        println!("Author looking for next sequenced message...");
        let ids = author.gen_next_msg_ids(multi_branching_flag == 1_u8, retry.clone());
        exists = false;
        for id in ids.iter() {
            next_id = id.1.clone();
            seq_num = id.2.clone();

            let msg = transport.recv_message_with_options(&next_id, multi_branching_flag.clone(), recv_opt).ok();
            if msg.is_none() {
                continue
            }
            let mut unwrapped = msg.unwrap();
            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                println!("\nMessage exists at {}", &preparsed.header.link.rel());

                match stdString::from_utf8(preparsed.header.content_type.0[..].to_vec()).unwrap().as_str() {
                    message::tagged_packet::TYPE => {
                        let _unwrapped = author.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break
                    },
                    message::sequence::TYPE => {
                        let msgid = author.unwrap_sequence(preparsed.clone()).unwrap();
                        println!("Found sequenced message...");
                        let msg = transport.recv_message_with_options(&msgid, multi_branching_flag, recv_opt).ok();
                        author.store_state(id.0.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    },
                    _ => {
                        // If message is found from self, internal state needs to be updated for next round
                        if id.0.as_bytes().eq(author.get_pk().as_bytes()) {
                            println!("Found previous message sent by self, updating sequence state...");
                        } else {
                            println!("Not a recognised type")
                        }
                        break
                    }
                }
            }

            if !(multi_branching_flag == 1_u8) {
                author.store_state_for_all(next_id.clone(), seq_num);
            }
            retry = false;
            exists = true;
        }

        if !exists {
            if !&retry {
                exists = true;
                retry = true;
                continue;
            }
            println!("No more messages in sequence.\n");
        }
    }
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
    let result = example(&mut client, send_opt, recv_opt, &seed1);
    if result.is_err() {
        println!("Error in test: {:?}", result.err());
    } else {
        println!("Test completed!!")
    }
}
