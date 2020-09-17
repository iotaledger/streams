#![allow(non_snake_case)]
use crate::{
    api::tangle::{
        Address,
        Author,
        Subscriber,
        Transport,
    },
    message,
};
use anyhow::{
    ensure,
    Result,
};
use iota_streams_app::{
    message::HasLink,
    transport::tangle::PAYLOAD_BYTES,
};
use iota_streams_core::{
    prelude::string::ToString,
    println,
};
use iota_streams_ddml::types::*;

pub fn example<T: Transport>(transport: &mut T) -> Result<()>
where
    T::SendOptions: Default,
    T::RecvOptions: Default,
{
    let encoding = "utf-8";
    let multi_branching = false;
    let mut author = Author::new("AUTHOR9SEED", encoding, PAYLOAD_BYTES, multi_branching);

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES);
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", encoding, PAYLOAD_BYTES);

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("announce");
    let (announcement_address, announcement_tag) = {
        let msg = &author.announce()?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        println!("  sent");
        (msg.link.appinst.to_string(), msg.link.msgid.to_string())
    };
    let announcement_link = Address::from_str(&announcement_address, &announcement_tag).unwrap();

    {
        println!("  recving");
        let msg = transport.recv_message(&announcement_link)?;
        println!("  parsing header");
        let preparsed = msg.parse_header()?;
        println!("  header parsed");
        ensure!(
            preparsed.check_content_type(message::ANNOUNCE),
            "bad message type: {}",
            preparsed.header.content_type
        );

        subscriberA.unwrap_announcement(preparsed.clone())?;
        ensure!(
            author.channel_address() == subscriberA.channel_address(),
            "bad channel address"
        );
        subscriberB.unwrap_announcement(preparsed)?;
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "bad channel address"
        );
        ensure!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            "bad announcement address"
        );
        // ensure!(subscriberA
        // .author_sig_public_key()
        // .as_ref()
        // .map_or(false, |pk| pk.bytes() == announcement_link.base().bytes()),
        // "bad announcement address");
    }

    println!("sign packet");
    let signed_packet_link = {
        let (msg, _) = author.sign_packet(&announcement_link, &public_payload, &masked_payload)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link.clone()
    };
    println!("  at {}", signed_packet_link.rel());

    {
        let msg = transport.recv_message(&signed_packet_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::SIGNED_PACKET), "bad message type");
        let (_pk, unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "bad unwrapped public payload");
        ensure!(masked_payload == unwrapped_masked, "bad unwrapped masked payload");
    }

    println!("subscribe");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link.clone()
    };

    {
        let msg = transport.recv_message(&subscribeB_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::SUBSCRIBE), "bad message type");
        author.unwrap_subscribe(preparsed)?;
    }

    println!("share keyload for everyone");
    let keyload_link = {
        let (msg, _) = author.share_keyload_for_everyone(&announcement_link)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link
    };

    {
        let msg = transport.recv_message(&keyload_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::KEYLOAD), "invalid message type");
        let resultA = subscriberA.unwrap_keyload(preparsed.clone());
        ensure!(resultA.is_err(), "failed to unwrap keyload");
        subscriberB.unwrap_keyload(preparsed)?;
    }

    println!("tag packet");
    let tagged_packet_link = {
        let (msg, _) = author.tag_packet(&keyload_link, &public_payload, &masked_payload)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link.clone()
    };

    {
        let msg = transport.recv_message(&tagged_packet_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::TAGGED_PACKET), "bad message type");
        let resultA = subscriberA.unwrap_tagged_packet(preparsed.clone());
        ensure!(resultA.is_err(), "failed to unwrap tagged packet");
        let (unwrapped_public, unwrapped_masked) = subscriberB.unwrap_tagged_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public, "bad unwrapped public payload");
        ensure!(masked_payload == unwrapped_masked, "bad unwrapped masked payload");
    }

    {
        let keyload = transport.recv_message(&keyload_link)?;
        let preparsed = keyload.parse_header()?;
        ensure!(preparsed.check_content_type(message::KEYLOAD), "bad message type");
        subscriberB.unwrap_keyload(preparsed)?;
    }

    // println!("unsubscribe");
    // let unsubscribe_link = {
    // let (msg, _) = subscriberB.unsubscribe(&subscribeB_link)?;
    // println!("  {}", msg);
    // transport.send_message(&msg)?;
    // msg.link
    // };
    //
    // {
    // let (msg, _) = transport.recv_message(&unsubscribe_link)?;
    // let preparsed = msg.parse_header()?;
    // ensure!(preparsed.check_content_type(message::unSUBSCRIBE));
    // author.unwrap_unsubscribe(preparsed)?;
    // }

    Ok(())
}

#[test]
fn run_basic_scenario() {
    let mut transport = crate::api::tangle::BucketTransport::new();
    assert!(dbg!(example(&mut transport)).is_ok());
}
