use iota_streams::{
    app::{
        message::HasLink,
        transport::tangle::PAYLOAD_BYTES,
    },
    app_channels::api::tangle::{
        Author,
        Subscriber,
        Transport,
    },
    core::{
        panic_if_not,
        prelude::Rc,
        print,
        println,
        try_or,
        Errors::*,
        Result,
    },
    ddml::types::*,
};

use core::cell::RefCell;

use super::utils;

pub fn example<T: Transport>(transport: Rc<RefCell<T>>, multi_branching: bool, seed: &str) -> Result<()> {
    let encoding = "utf-8";
    let mut author = Author::new(seed, encoding, PAYLOAD_BYTES, multi_branching, transport.clone());
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES, transport.clone());
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", encoding, PAYLOAD_BYTES, transport.clone());
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", encoding, PAYLOAD_BYTES, transport.clone());

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce()?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  Author     : {}", author);
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    {
        subscriberA.receive_announcement(&announcement_link)?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            author.channel_address() == subscriberA.channel_address(),
            ApplicationInstanceMismatch(String::from("A"))
        )?;
        subscriberB.receive_announcement(&announcement_link)?;
        print!("  SubscriberB: {}", subscriberB);
        try_or!(
            author.channel_address() == subscriberB.channel_address(),
            ApplicationInstanceMismatch(String::from("B"))
        )?;
        subscriberC.receive_announcement(&announcement_link)?;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(
            author.channel_address() == subscriberC.channel_address(),
            ApplicationInstanceMismatch(String::from("C"))
        )?;

        try_or!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            ApplicationInstanceMismatch(String::from("A"))
        )?;
        try_or!(
            subscriberA.is_multi_branching() == author.is_multi_branching(),
            BranchingFlagMismatch(String::from("A"))
        )?;
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Subscribe A");
    {
        author.receive_subscribe(&subscribeA_link)?;
        print!("  Author     : {}", author);
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberB: {}", subscriberB);
        msg
    };

    println!("\nHandle Subscribe B");
    {
        author.receive_subscribe(&subscribeB_link)?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let previous_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Keyload");
    {
        let resultC = subscriberC.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC == false, SubscriberAccessMismatch(String::from("C")))?;
        subscriberA.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberB: {}", subscriberB);
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        print!("  Author     : {}", author);
        let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA);

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Tagged packet 1");
    {
        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&previous_msg_link)?;
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let resultC = subscriberC.receive_tagged_packet(&previous_msg_link);
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC.is_err(), SubscriberAccessMismatch(String::from("C")))?;
    }

    println!("\nTagged packet 2 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB);

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let (msg, seq) = subscriberB.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  SubscriberB: {}", subscriberB);
        msg
    };

    println!("\nHandle Tagged packet 4");
    {
        let (unwrapped_public, unwrapped_masked) = subscriberA.receive_tagged_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let resultC = subscriberC.receive_tagged_packet(&previous_msg_link);
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC.is_err(), SubscriberAccessMismatch(String::from("C")))?;
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author);

    println!("\nSigned packet");
    let previous_msg_link = {
        let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberB.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberB: {}", subscriberB);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    Ok(())
}
