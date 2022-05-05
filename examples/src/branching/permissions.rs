use iota_streams::{
    app::id::permission::*,
    app_channels::{
        api::{
            psk_from_seed,
            pskid_from_psk,
            Transport,
            UserBuilder,
        },
        UserIdentity,
    },
    core::{
        assert,
        print,
        println,
        Result,
    },
    ddml::types::*,
};

use super::utils;

pub async fn example<T: Transport>(transport: T, seed: &str) -> Result<()> {
    // Generate a simple PSK for storage by users
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);

    let mut author = UserBuilder::new()
        .with_identity(UserIdentity::new(seed))
        .with_transport(transport.clone())
        .build()?;

    let mut subscriberA = UserBuilder::new()
        .with_identity(UserIdentity::new("SUBSCRIBERA9SEED"))
        .with_transport(transport.clone())
        .build()?;
    let mut subscriberB = UserBuilder::new()
        .with_identity(UserIdentity::new("SUBSCRIBERB9SEED"))
        .with_transport(transport.clone())
        .build()?;
    let mut subscriberC = UserBuilder::new()
        .with_identity(UserIdentity::new_from_psk(pskid, psk))
        .with_transport(transport.clone())
        .build()?;

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
        subscriberA.receive_message(&announcement_link).await?;
        print!("  SubscriberA: {}", subscriberA);

        subscriberB.receive_message(&announcement_link).await?;
        print!("  SubscriberB: {}", subscriberB);

        subscriberC.receive_message(&announcement_link).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    // Predefine Subscriber A
    println!("\nAuthor Predefines Subscriber A and Psk");
    author.store_new_subscriber(*subscriberA.id(), subA_xkey)?;
    author.store_psk(pskid, psk)?;

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
    let (previous_msg_link, previous_msg_seq) = {
        let (msg, seq) = author.send_keyload(&announcement_link, &permissions).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!("\nHandle Keyload");
    {
        subscriberA.receive_message(&previous_msg_seq).await?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_message(&previous_msg_seq).await?;
        print!("  SubscriberB: {}", subscriberB);
        subscriberC.receive_message(&previous_msg_seq).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    println!("\nSigned packet 1 - Author");
    let (previous_msg_link, previous_msg_seq) = {
        let (msg, seq) = author
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!("\nHandle Signed packet 1");
    {
        subscriberA.receive_message(&previous_msg_seq).await?;
        print!("  SubscriberA: {}", subscriberA);
    }

    println!("\nSubscriber B fetching transactions...");
    let mut count;

    // This verifies correct
    count = utils::fetch_next_messages(&mut subscriberB).await?;
    assert!(count == 1);

    // This breaks
    // assert!(utils::fetch_next_messages(&mut subscriberB).await? == 1);

    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1);

    println!("\nTagged packet 1 - SubscriberB (subscriber B does NOT have Write permission)");
    let (_previous_msg_link_wrong, _previous_msg_seq_wrong) = {
        let (msg, seq) = subscriberB
            .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberB: {}", subscriberB);
        (msg, seq)
    };
    // Not found by anyone as its not a writer
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
    let (previous_msg_link, previous_msg_seq) = {
        let (msg, seq) = subscriberA
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        (msg, seq)
    };

    println!("\nauthor fetching Signed packet from Subscriber A...");
    {
        author.receive_message(&previous_msg_seq).await?;
        print!("  Author: {}", author);
    }

    println!("\nAuthor fetching transactions...");
    count = utils::fetch_next_messages(&mut author).await?; // We fetched manually
    assert!(count == 0);
    println!("\nSubscriber B fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberB).await?;
    assert!(count == 1); // Sub B send his own which everyone ignored
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1);

    println!("\nSigned packet 3 - SubscriberA (subscriber A has Write permission");
    let (_previous_msg_link, _previous_msg_seq) = {
        let (msg, seq) = subscriberA
            .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        (msg, seq)
    };

    println!("\nAuthor fetching transactions...");
    count = utils::fetch_next_messages(&mut author).await?;
    assert!(count == 1);
    println!("\nSubscriber B fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberB).await?;
    assert!(count == 1);
    println!("\nSubscriber C fetching transactions...");
    count = utils::fetch_next_messages(&mut subscriberC).await?;
    assert!(count == 1);

    Ok(())
}
