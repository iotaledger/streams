#![allow(non_snake_case)]
use failure::{
    ensure,
    Fallible,
};
use iota_lib_rs::prelude::iota_client;
use iota_streams_app::{
    message::HasLink,
    transport::tangle::client::SendTrytesOptions,
};
use iota_streams_app_channels::{
    api::tangle::{
        Address,
        Author,
        Subscriber,
        Transport,
    },
    message,
};
use iota_streams_core::tbits::Tbits;
use iota_streams_protobuf3::types::Trytes;
use std::str::FromStr;

fn example<T: Transport>(transport: &mut T, send_opt: T::SendOptions, recv_opt: T::RecvOptions) -> Fallible<()>
where
    T::SendOptions: Copy,
    T::RecvOptions: Copy,
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
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        (msg.link.appinst.to_string(), msg.link.msgid.to_string())
    };
    let announcement_link = Address::from_str(&announcement_address, &announcement_tag).unwrap();

    {
        let msg = transport.recv_message_with_options(&announcement_link, recv_opt)?;
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
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link.clone()
    };
    println!("  at {}", signed_packet_link.rel());

    {
        let msg = transport.recv_message_with_options(&signed_packet_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::signed_packet::TYPE));
        let (unwrapped_public, unwrapped_masked) = subscriberA.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
    }

    println!("subscribe");
    let subscribeB_link = {
        let msg = subscriberB.subscribe(&announcement_link)?;
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&subscribeB_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::subscribe::TYPE));
        author.unwrap_subscribe(preparsed)?;
    }

    println!("share keyload for everyone");
    let keyload_link = {
        let msg = author.share_keyload_for_everyone(&announcement_link)?;
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&keyload_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::keyload::TYPE));
        let resultA = subscriberA.unwrap_keyload(preparsed.clone());
        ensure!(resultA.is_err());
        subscriberB.unwrap_keyload(preparsed)?;
    }

    println!("tag packet");
    let tagged_packet_link = {
        let msg = author.tag_packet(&keyload_link, &public_payload, &masked_payload)?;
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link.clone()
    };

    {
        let msg = transport.recv_message_with_options(&tagged_packet_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::tagged_packet::TYPE));
        let resultA = subscriberA.unwrap_tagged_packet(preparsed.clone());
        ensure!(resultA.is_err());
        let (unwrapped_public, unwrapped_masked) = subscriberB.unwrap_tagged_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
    }

    {
        let keyload = transport.recv_message_with_options(&keyload_link, recv_opt)?;
        let preparsed = keyload.parse_header()?;
        ensure!(preparsed.check_content_type(message::keyload::TYPE));
        subscriberB.unwrap_keyload(preparsed)?;
    }

    println!("change key");
    let change_key_link = {
        let msg = author.change_key(&announcement_link)?;
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&change_key_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::change_key::TYPE));
        subscriberB.unwrap_change_key(preparsed)?;
    }

    println!("unsubscribe");
    let unsubscribe_link = {
        let msg = subscriberB.unsubscribe(&subscribeB_link)?;
        println!("  {}", msg.link.msgid);
        transport.send_message_with_options(&msg, send_opt)?;
        msg.link
    };

    {
        let msg = transport.recv_message_with_options(&unsubscribe_link, recv_opt)?;
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.check_content_type(message::unsubscribe::TYPE));
        author.unwrap_unsubscribe(preparsed)?;
    }

    Ok(())
}

fn main() {
    let mut client = iota_client::Client::new("https://nodes.devnet.iota.org:443");
    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 10;
    let recv_opt = ();
    let _result = dbg!(example(&mut client, send_opt, recv_opt));
}
