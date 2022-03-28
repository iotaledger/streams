use iota_streams::{
    app_channels::api::tangle::{
        Author,
        ChannelType,
        Subscriber,
        Transport,
    },
    core::{
        assert,
        println,
        Result,
    },
    ddml::types::*,
};

use super::utils;
use std::{
    thread::sleep,
    time::Duration,
};

pub async fn example<T: Transport>(transport: T, channel_type: ChannelType, seed: &str) -> Result<()> {
    let mut author = Author::new(seed, channel_type.clone(), transport.clone()).await;
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone()).await;

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce().await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    subscriberA.receive_announcement(&announcement_link).await?;

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };

    println!("\nHandle Subscribe A");
    author.receive_subscribe(&subscribeA_link).await?;

    println!("\nShare keyload");
    let mut previous_msg_link = {
        let (msg, _seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };

    for i in 1..6 {
        println!("Signed packet {} - Author", i);
        previous_msg_link = {
            let (msg, _seq) = author
                .send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)
                .await?;
            println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Subscriber A fetching transactions...");
    utils::fetch_next_messages(&mut subscriberA).await?;

    for i in 6..11 {
        println!("Tagged packet {} - SubscriberA", i);
        previous_msg_link = {
            let (msg, seq) = subscriberA
                .send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)
                .await?;
            println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
            if let Some(seq) = seq {
                println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
            }
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Author fetching transactions...");
    utils::fetch_next_messages(&mut author).await?;

    println!("\n\nTime to try to recover the instance...");
    let mut new_author = Author::recover(seed, &announcement_link, channel_type, transport.clone()).await?;
    new_author.sync_state().await?;

    let state = new_author.fetch_state()?;
    let old_state = author.fetch_state()?;

    let mut latest_link = &announcement_link;

    for (pk, cursor) in old_state.iter() {
        let mut exists = false;
        for (p, c) in state.iter() {
            if pk == p && cursor.link == c.link && cursor.branch_no == c.branch_no && cursor.seq_no == c.seq_no {
                // Set latest link for sequencing later
                latest_link = &cursor.link;
                exists = true
            }
        }
        assert!(
            exists,
            "cursor '{}' present in the original state but not in the new",
            cursor
        );
    }

    println!("States match...\nSending next sequenced message... {}", latest_link.msgid);
    let (last_msg, _seq) = new_author
        .send_signed_packet(latest_link, &public_payload, &masked_payload)
        .await?;
    println!("  msg => <{}> <{:x}>", last_msg.msgid, last_msg.to_msg_index());

    // Wait a second for message to propagate
    sleep(Duration::from_secs(1));
    println!("\nSubscriber A fetching transactions...");
    let msgs = subscriberA.fetch_next_msgs().await?;
    assert!(!msgs.is_empty());

    let mut matches = false;
    for msg in msgs {
        if last_msg == msg.link {
            matches = true
        }
    }
    assert!(matches);

    println!("Last message matches, recovery, sync and send successful");

    println!("\nTesting export/import");
    let exported = author.export("Password").await?;
    println!("Author exported...");
    let new_auth = Author::import(&exported, "Password", transport).await?;
    println!("Author imported...");
    let retrieved_announcement = new_auth.announcement_link().unwrap();
    assert!(retrieved_announcement == announcement_link);
    println!("Imported Author announcement message matches original\n");

    Ok(())
}
