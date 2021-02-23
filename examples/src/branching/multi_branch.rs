use iota_streams::{
    app::{message::HasLink, transport::tangle::PAYLOAD_BYTES},
    app_channels::api::tangle::{Author, Subscriber, Transport},
    core::{print, println, try_or, Errors::*, Result, LOCATION_LOG},
    ddml::types::*,
};

use super::utils;

pub async fn example<T>(transport: T, multi_branching: bool, seed: &str) -> Result<()>
where
    T: Transport +  Clone,
{
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
        let msg = author.send_announce().await.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Announce Channel");
    {
        subscriberA.receive_announcement(&announcement_link).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            author.channel_address() == subscriberA.channel_address(),
            ApplicationInstanceMismatch(String::from("A"))
        )?;
        subscriberB.receive_announcement(&announcement_link).await.unwrap();
        print!("  SubscriberB: {}", subscriberB);
        try_or!(
            author.channel_address() == subscriberB.channel_address(),
            ApplicationInstanceMismatch(String::from("B"))
        )?;
        subscriberC.receive_announcement(&announcement_link).await.unwrap();
        print!("  SubscriberC: {}", subscriberC);
        try_or!(
            author.channel_address() == subscriberC.channel_address(),
            ApplicationInstanceMismatch(String::from("C"))
        )?;

        try_or!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            ApplicationInstanceAnnouncementMismatch(String::from("C"))
        )?;
        try_or!(
            subscriberA.is_multi_branching() == author.is_multi_branching(),
            BranchingFlagMismatch(String::from("A"))
        )?;
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link).await.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Subscribe A");
    {
        author.receive_subscribe(&subscribeA_link).await.unwrap();
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA]");
    let keyload_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await.unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  Author     : {}", author);
        seq
    };

    println!("\nHandle Share keyload for everyone [SubscriberA]: {}", &keyload_link);
    {
        let msg_tag = subscriberA.receive_sequence(&keyload_link).await.unwrap();
        print!("  Author     : {}", author);

        let resultB = subscriberB.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberB: {}", subscriberB);
        try_or!(resultB == false, SubscriberAccessMismatch(String::from("B")))?;

        let resultC = subscriberC.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC == false, SubscriberAccessMismatch(String::from("C")))?;

        println!("Subscriber a unwrapping");
        subscriberA.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA).await;

    println!("\nTagged packet 1 - SubscriberA");
    let tagged_packet_link = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await
            .unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  SubscriberA: {}", subscriberA);
        seq
    };

    println!("\nHandle Tagged packet 1 - SubscriberA");
    {
        let msg_tag = subscriberA.receive_sequence(&tagged_packet_link).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);

        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&msg_tag).await.unwrap();
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let resultB = subscriberB.receive_tagged_packet(&msg_tag).await;
        print!("  SubscriberB: {}", subscriberB);
        try_or!(resultB.is_err(), SubscriberAccessMismatch(String::from("B")))?;

        let resultC = subscriberC.receive_tagged_packet(&msg_tag).await;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC.is_err(), SubscriberAccessMismatch(String::from("C")))?;
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author).await;

    println!("\nSigned packet");
    let signed_packet_link = {
        let (msg, seq) = author
            .send_signed_packet(&tagged_packet_link, &public_payload, &masked_payload)
            .await
            .unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  Author     : {}", author);
        seq
    };

    println!("\nHandle Signed packet");
    {
        let msg_tag = subscriberA.receive_sequence(&signed_packet_link).await.unwrap();
        print!("  Author     : {}", author);

        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberA.receive_signed_packet(&msg_tag).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link).await.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberB: {}", subscriberB);
        msg
    };

    println!("\nHandle Subscribe B");
    {
        author.receive_subscribe(&subscribeB_link).await.unwrap();
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let keyload_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await.unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  Author     : {}", author);
        seq
    };

    println!("\nHandle Share keyload for everyone [SubscriberA, SubscriberB]");
    {
        let msg_tag = subscriberA.receive_sequence(&keyload_link).await.unwrap();
        print!("  Author     : {}", author);

        let resultC = subscriberC.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberC: {}", subscriberC);
        try_or!(!resultC, SubscriberAccessMismatch(String::from("C")))?;
        subscriberA.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_keyload(&msg_tag).await.unwrap();
        print!("  SubscriberB: {}", subscriberB);
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA).await;

    println!("\nTagged packet 2 - SubscriberA");
    let tagged_packet_link = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await
            .unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  SubscriberA: {}", subscriberA);
        seq
    };

    println!("\nHandle Tagged packet 2 - SubscriberA");
    {
        let msg_tag = subscriberA.receive_sequence(&tagged_packet_link).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);

        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&msg_tag).await.unwrap();
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let resultC = subscriberC.receive_tagged_packet(&msg_tag).await;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC.is_err(), SubscriberAccessMismatch(String::from("C")))?;
    }

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB).await;

    println!("\nTagged packet 3 - SubscriberB");
    let tagged_packet_link = {
        let (msg, seq) = subscriberB
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await
            .unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  SubscriberB: {}", subscriberB);
        seq
    };

    println!("\nHandle Tagged packet 3 - SubscriberB");
    {
        let msg_tag = subscriberA.receive_sequence(&tagged_packet_link).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);

        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&msg_tag).await.unwrap();
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let resultC = subscriberC.receive_tagged_packet(&msg_tag).await;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(resultC.is_err(), SubscriberAccessMismatch(String::from("C")))?;
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author).await;

    println!("\nSigned packet");
    let signed_packet_link = {
        let (msg, seq) = author
            .send_signed_packet(&tagged_packet_link, &public_payload, &masked_payload)
            .await
            .unwrap();
        let seq = seq.unwrap();
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        println!("  seq => <{}> {:?}", seq.msgid, seq);
        print!("  Author     : {}", author);
        seq
    };

    println!("\nHandle Signed packet");
    {
        let msg_tag = subscriberA.receive_sequence(&signed_packet_link).await.unwrap();
        print!("  Author     : {}", author);

        println!("\nSubscriber A fetching transactions...");
        utils::s_fetch_next_messages(&mut subscriberA).await;
        println!("\nSubscriber B fetching transactions...");
        utils::s_fetch_next_messages(&mut subscriberB).await;

        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberA.receive_signed_packet(&msg_tag).await.unwrap();
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberB.receive_signed_packet(&msg_tag).await.unwrap();
        print!("  SubscriberB: {}", subscriberB);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    Ok(())
}
