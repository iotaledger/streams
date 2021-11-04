use iota_streams::{
    app::message::HasLink,
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::{
            Author,
            ChannelType,
            Subscriber,
            Transport,
        },
    },
    core::{
        panic_if_not,
        prelude::HashMap,
        print,
        println,
        try_or,
        Errors::*,
        Result,
    },
    ddml::types::*,
};

use super::utils;
use iota_streams::core::iota_identity::crypto::KeyPair;
use iota_streams::core::iota_identity::iota::{Client as DIDClient, IotaDID};
use iota_streams::app::id::DIDInfo;

pub async fn example<'a, T: 'a + Transport>(keypair: Option<(String, KeyPair, DIDClient)>, transport: T, channel_type: ChannelType, seed: &str) -> Result<()> {
    let mut author = match keypair {
        Some((did, keypair, did_client)) => {
            let (author, _author_keypair) = Author::new_with_did(
                seed,
                channel_type,
                transport.clone(),
                DIDInfo {
                    did: Some(IotaDID::parse(did)?),
                    key_fragment: "streams-key-1".to_string(),
                    did_client,
                    url: transport.get_url()
                },
                &keypair
            ).await?;
            author
        },
        None => Author::new(seed, channel_type, transport.clone())
    };
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone());
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", transport.clone());
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", transport);

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce().await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        print!("  Author     : {}", author);
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    {
        subscriberA.receive_announcement(&announcement_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            author.channel_address() == subscriberA.channel_address(),
            ApplicationInstanceMismatch(String::from("A"))
        )?;
        subscriberB.receive_announcement(&announcement_link).await?;
        print!("  SubscriberB: {}", subscriberB);
        try_or!(
            author.channel_address() == subscriberB.channel_address(),
            ApplicationInstanceMismatch(String::from("B"))
        )?;
        subscriberC.receive_announcement(&announcement_link).await?;
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

    // Predefine Subscriber A
    println!("\nAuthor Predefines Subscriber A");
    author.store_new_subscriber(*subscriberA.get_public_key())?;

    // Generate a simple PSK for storage by users
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);
    author.store_psk(pskid, psk)?;
    subscriberC.store_psk(pskid, psk)?;

    // Fetch state of subscriber for comparison after reset
    let sub_a_start_state: HashMap<_, _> = subscriberA.fetch_state()?.into_iter().collect();

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        print!("  SubscriberB: {}", subscriberB);
        msg
    };

    println!("\nHandle Subscribe B");
    {
        author.receive_subscribe(&subscribeB_link).await?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB, PSK]");
    let previous_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Keyload");
    {
        subscriberA.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberB: {}", subscriberB);
        subscriberC.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        let (msg, seq) = author
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberA.receive_signed_packet(&previous_msg_link).await?;
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
    utils::s_fetch_next_messages(&mut subscriberA).await;
    println!("\nSubscriber C fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberC).await;

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Tagged packet 1");
    {
        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&previous_msg_link).await?;
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (unwrapped_public, unwrapped_masked) = subscriberC.receive_tagged_packet(&previous_msg_link).await?;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nTagged packet 2 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB).await;
    println!("\nSubscriber C fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberC).await;

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let (msg, seq) = subscriberB
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  SubscriberB: {}", subscriberB);
        msg
    };

    println!("\nHandle Tagged packet 4");
    {
        let (unwrapped_public, unwrapped_masked) = subscriberA.receive_tagged_packet(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        println!("Subscriber C unwrapping");
        let (unwrapped_public, unwrapped_masked) = subscriberC.receive_tagged_packet(&previous_msg_link).await?;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nSubscriber fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberC).await;

    println!("\nTagged packet 5 - SubscriberC");
    let previous_msg_link = {
        let (msg, seq) = subscriberC
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> {:x}", msg.msgid, msg.to_msg_index());
        panic_if_not(seq.is_none());
        print!("  SubscriberC: {}", subscriberC);
        msg
    };

    println!("\nHandle Tagged packet 5");
    {
        let (unwrapped_public, unwrapped_masked) = subscriberA.receive_tagged_packet(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (unwrapped_public, unwrapped_masked) = subscriberB.receive_tagged_packet(&previous_msg_link).await?;
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

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author).await;

    println!("\nSigned packet");
    let signed_packet_link = {
        let (msg, seq) = author
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());

        panic_if_not(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberA.receive_signed_packet(&signed_packet_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            PublicPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (_signer_pk, unwrapped_public, unwrapped_masked) =
            subscriberB.receive_signed_packet(&signed_packet_link).await?;
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

    println!("\nSubscriber A checking previous message");
    {
        let msg = subscriberA.fetch_prev_msg(&signed_packet_link).await?;
        println!("Found message: {}", msg.link.msgid);
        try_or!(
            msg.link == previous_msg_link,
            LinkMismatch(msg.link.msgid.to_string(), previous_msg_link.msgid.to_string())
        )?;
        println!("  SubscriberA: {}", subscriberA);
    }

    println!("\nSubscriber B checking 5 previous messages");
    {
        let msgs = subscriberB.fetch_prev_msgs(&signed_packet_link, 5).await?;
        try_or!(msgs.len() == 5, ValueMismatch(5, msgs.len()))?;
        println!("Found {} messages", msgs.len());
        println!("  SubscriberB: {}", subscriberB);
    }

    subscriberA.reset_state()?;
    let new_state: HashMap<_, _> = subscriberA.fetch_state()?.into_iter().collect();

    println!("\nSubscriber A resetting state");
    let mut matches = false;
    for (old_pk, old_cursor) in sub_a_start_state.iter() {
        if new_state.contains_key(old_pk) && new_state[old_pk].link == old_cursor.link {
            matches = true
        }
        try_or!(matches, StateMismatch)?;
    }
    println!("Subscriber states matched");

    println!("\nAuthor unsubscribes Subscriber A");
    author.remove_subscriber(*subscriberA.get_public_key())?;

    println!("\nSubscriber B sending unsubscribe message");
    let unsub_link = subscriberB.send_unsubscribe(&subscribeB_link).await?;
    println!("Author receiving unsubscribe");
    author.receive_unsubscribe(&unsub_link).await?;

    println!("\nAuthor sending new keyload to all subscribers");
    let new_keyload = author.send_keyload_for_everyone(&announcement_link).await?;
    println!("Subscriber B checking that they do not have access to new keyload");
    try_or!(
        !subscriberB.receive_keyload(&new_keyload.0).await?,
        SubscriberAccessMismatch("B".to_string())
    )?;
    println!("Subscriber B does not have access to the new keyload");

    Ok(())
}
