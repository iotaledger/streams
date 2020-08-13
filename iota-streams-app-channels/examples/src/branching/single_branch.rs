use iota_streams_app_channels::{
    api::tangle::{
        Address,
        Author,
        Subscriber,
        Transport,
    },
    message,
};
use iota_streams_protobuf3::types::*;
use iota_streams_app::message::HasLink;

use anyhow::{
    ensure,
    Result,
};

use heapless::consts::U256;
use heapless::Vec;

#[path = "utils.rs"]
mod utils;

pub fn example<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions, seed: &str) -> Result<()>
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
        ensure!(subscriberA.get_branching_flag() == author.get_branching_flag(),
            "Subscribers should have the same branching flag as the author after unwrapping");
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.subscribe(&announcement_link)?;
        transport.send_message_with_options(&msg, send_opt)?;
        println!("Subscribe at {}", msg.link.msgid);
        msg.link
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
        transport.send_message_with_options(&msg, send_opt)?;
        println!("Subscribe at {}", msg.link.msgid);
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&subscribeB_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::subscribe::TYPE), "Wrong message type: {}", preparsed.header.content_type);
        author.unwrap_subscribe(preparsed)?;
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let previous_msg_link = {
        let msg = author.share_keyload_for_everyone(&announcement_link).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Keyload message at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::keyload::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let resultC = subscriberC.unwrap_keyload(preparsed.clone());
        ensure!(resultC.is_err(), "SubscriberC should not be able to unwrap the keyload");

        subscriberA.unwrap_keyload(preparsed.clone())?;
        subscriberB.unwrap_keyload(preparsed)?
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        let msg = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Signed packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::signed_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA, transport, recv_opt, multi_branching_flag.clone());

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let msg = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = author.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
        ensure!(resultC.is_err(), "Subscriber C should not be able to access this message");
    }

    println!("\nTagged packet 2 - SubscriberA");
    let previous_msg_link = {
        let msg = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);
    }

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let msg = subscriberA.tag_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);
    }

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB, transport, recv_opt, multi_branching_flag.clone());

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let msg = subscriberB.tag_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Tagged packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(&message::tagged_packet::TYPE), "Wrong message type: {}", preparsed.header.content_type);

        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_tagged_packet(preparsed.clone())?;
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.unwrap_tagged_packet(preparsed);
        ensure!(resultC.is_err(), "Subscriber C should not be able to access this message");
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author, transport, recv_opt, multi_branching_flag.clone());

    println!("\nSigned packet");
    let previous_msg_link = {
        let msg = author.sign_packet(&previous_msg_link, &public_payload, &masked_payload).unwrap();
        transport.send_message_with_options(&msg.0, send_opt);
        println!("Signed packet at {}", &msg.0.link.msgid);
        msg.0.link
    };

    {
        let msg = transport.recv_message_with_options(&previous_msg_link, multi_branching_flag.clone(), recv_opt).unwrap();
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
