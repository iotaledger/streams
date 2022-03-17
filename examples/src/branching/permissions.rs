use iota_streams::{
    app::{
        message::HasLink,
        permission::*,
    },
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
    author.store_new_subscriber(*subscriberA.id(), subA_xkey)?;

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

    let psk_perm = Permission::ReadWrite(pskid.into(), PermissionDuration::Perpetual);
    let permissions = vec![&psk_perm];

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB, PSK]");
    let previous_msg_link = {
        let (msg, seq) = author.send_keyload(&announcement_link, permissions).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Keyload");
    {
        subscriberA.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        /*subscriberB.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberB: {}", subscriberB);
        subscriberC.receive_keyload(&previous_msg_link).await?;
        print!("  SubscriberC: {}", subscriberC); */
    }

    Ok(())
}
