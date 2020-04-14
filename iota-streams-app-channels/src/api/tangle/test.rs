#![allow(non_snake_case)]
use crate::{
    api::tangle::{
        Address,
        Author,
        BucketTransport,
        Subscriber,
        Transport,
    },
    message,
};
use failure::{
    ensure,
    Fallible,
};
use iota_streams_app::message::HasLink;
use iota_streams_core::tbits::Tbits;
use iota_streams_protobuf3::types::Trytes;
use std::str::FromStr;

fn example<T: Transport>(transport: &mut T) -> Fallible<()>
where
    T::SendOptions: Default,
    T::RecvOptions: Default,
{
    let mut author = Author::new("AUTHOR9SEED", 2, true);
    println!("Channel address = {}", author.channel_address());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", false);
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", true);

    let public_payload = Trytes(Tbits::from_str("PUBLICPAYLOAD").unwrap());
    let masked_payload = Trytes(Tbits::from_str("MASKEDPAYLOAD").unwrap());

    println!("announce");
    let (announcement_address, announcement_tag) = {
        let msg = &author.announce()?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        (msg.link.appinst.to_string(), msg.link.msgid.to_string())
    };
    let announcement_link = Address::from_str(&announcement_address, &announcement_tag).unwrap();

    {
        let msg = transport.recv_message(&announcement_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::announce::TYPE));

        subscriberA.unwrap_announcement(preparsed.clone())?;
        ensure!(author.channel_address() == subscriberA.channel_address().unwrap());
        subscriberB.unwrap_announcement(preparsed)?;
        ensure!(subscriberA.channel_address() == subscriberB.channel_address());
        ensure!(subscriberA
            .channel_address()
            .map_or(false, |appinst| appinst == announcement_link.base()));
        ensure!(subscriberA
            .author_mss_public_key()
            .as_ref()
            .map_or(false, |pk| pk.tbits() == announcement_link.base().tbits()));
    }

    println!("sign packet");
    let signed_packet_link = {
        let msg = author.sign_packet(&announcement_link, &public_payload, &masked_payload)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link.clone()
    };
    println!("  at {}", signed_packet_link.rel());

    {
        let msg = transport.recv_message(&signed_packet_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::signed_packet::TYPE));
        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
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
        ensure!(preparsed.check_content_type(message::subscribe::TYPE));
        author.unwrap_subscribe(preparsed)?;
    }

    println!("share keyload for everyone");
    let keyload_link = {
        let msg = author.share_keyload_for_everyone(&announcement_link)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link
    };

    {
        let msg = transport.recv_message(&keyload_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::keyload::TYPE));
        let resultA = subscriberA.unwrap_keyload(preparsed.clone());
        ensure!(resultA.is_err());
        subscriberB.unwrap_keyload(preparsed)?;
    }

    println!("tag packet");
    let tagged_packet_link = {
        let msg = author.tag_packet(&keyload_link, &public_payload, &masked_payload)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link.clone()
    };

    {
        let msg = transport.recv_message(&tagged_packet_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::tagged_packet::TYPE));
        let resultA = subscriberA.unwrap_tagged_packet(preparsed.clone());
        ensure!(resultA.is_err());
        let (unwrapped_public, unwrapped_masked) = subscriberB.unwrap_tagged_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
    }

    {
        let keyload = transport.recv_message(&keyload_link)?;
        let preparsed = keyload.parse_header()?;
        ensure!(preparsed.check_content_type(message::keyload::TYPE));
        subscriberB.unwrap_keyload(preparsed)?;
    }

    println!("change key");
    let change_key_link = {
        let msg = author.change_key(&announcement_link)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link
    };

    {
        let msg = transport.recv_message(&change_key_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::change_key::TYPE));
        subscriberB.unwrap_change_key(preparsed)?;
    }

    println!("unsubscribe");
    let unsubscribe_link = {
        let msg = subscriberB.unsubscribe(&subscribeB_link)?;
        println!("  {}", msg);
        transport.send_message(&msg)?;
        msg.link
    };

    {
        let msg = transport.recv_message(&unsubscribe_link)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::unsubscribe::TYPE));
        author.unwrap_unsubscribe(preparsed)?;
    }

    Ok(())
}

#[test]
fn run_basic_scenario() {
    let mut transport = BucketTransport::new();
    assert!(dbg!(example(&mut transport)).is_ok());
}
