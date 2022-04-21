use iota_streams::{
    app::id::permission::*,
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
        assert,
        print,
        println,
        try_or,
        Errors::*,
        Result,
    },
    ddml::types::*,
};

use iota_streams::app_channels::api::tangle::futures::TryStreamExt;
use iota_streams::app::message::HasLink;

use super::utils;

pub async fn example<T: Transport>(transport: T, channel_impl: ChannelType, seed: &str) -> Result<()> {
    let mut author = Author::new(seed, channel_impl, transport.clone()).await;
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone()).await;
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", transport.clone()).await;
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", transport).await;

    let subA_xkey = subscriberA.key_exchange_public_key()?;

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
        subscriberA.receive_msg(&announcement_link).await?;
        print!("  SubscriberA: {}", subscriberA);

        subscriberB.receive_msg(&announcement_link).await?;
        print!("  SubscriberB: {}", subscriberB);

        subscriberC.receive_msg(&announcement_link).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    // Predefine Subscriber A
    println!("\nAuthor Predefines Subscriber A");
    author.store_new_subscriber(*subscriberA.id(), subA_xkey)?;

    // Generate a simple PSK for storage by users, Subscriber C
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);
    author.store_psk(pskid, psk)?;
    subscriberC.store_psk(pskid, psk)?;

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

    // Only author and A can send, B and C will be ignored
    let sub_a_perm = Permission::ReadWrite(subscriberA.id().clone(), PermissionDuration::Perpetual);
    let sub_b_perm = Permission::Read(subscriberB.id().clone());
    let psk_perm = Permission::Read(pskid.into());
    let permissions = vec![sub_a_perm, sub_b_perm, psk_perm];

    println!("\nShare keyload for subscribers [SubscriberA, SubscriberB, PSK]");
    let previous_msg_link = {
        let (msg, _seq) = author.send_keyload(&announcement_link, &permissions).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Keyload");
    {
        subscriberA.receive_msg(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_msg(&previous_msg_link).await?;
        print!("  SubscriberB: {}", subscriberB);
        subscriberC.receive_msg(&previous_msg_link).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    println!("\nSigned packet 1 - Author");
    let previous_msg_link = {
        let (msg, _seq) = author
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Signed packet 1");
    {
        subscriberA.receive_msg(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
    }

    println!("\nSubscriber B fetching transactions...");
    let mut count = 0;
    
    // This verifies correct
    count = utils::fetch_next_messages(&mut subscriberB).await?;
    assert!(count == 1);

    // This breaks
    // assert!(utils::fetch_next_messages(&mut subscriberB).await? == 1);
    
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1);


    println!("\nTagged packet 1 - SubscriberB (subscriber B does NOT have Write permission)");
    let previous_msg_link_wrong = {
        let (msg, _) = subscriberB
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        print!("  SubscriberB: {}", subscriberB);
        msg
    };
    // Not found by subA
    println!("\nAuthor fetching transactions...");
    count = utils::fetch_next_messages(&mut author).await?;
    assert!(count == 0);
    println!("\nSubscriber A fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberA).await?;
    assert!(count == 0); 
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 0);

    println!("\nSigned packet 2 - SubscriberA (subscriber A has Write permission");
    let previous_msg_link = {
        let (msg, _) = subscriberA
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nauthor fetching Signed packet from Subscriber A...");
    author.receive_signed_packet(&previous_msg_link).await?;

    println!("\nAuthor fetching transactions...");
    count = utils::fetch_next_messages(&mut author).await?; // We fetched manually
    assert!(count == 0);
    println!("\nSubscriber B fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberB).await?; 
    assert!(count == 0); // Sub B send his own on this address and now has a faulty state
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1);

    println!("\nSigned packet 3 - SubscriberA (subscriber A has Write permission");
    let previous_msg_link = {
        let (msg, _) = subscriberA
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };

    println!("\nAuthor fetching transactions...");
    count = utils::fetch_next_messages(&mut author).await?;
    assert!(count == 1); // Author finds normally
    println!("\nSubscriber B fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberB).await?;
    assert!(count == 0); // B has a wrong state, thus doenst see it
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1); // C finds finds normally

    Ok(())
}
