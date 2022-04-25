use iota_streams::{
    app::message::HasLink,
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
        .with_identity(UserIdentity::new("SUBSCRIBERC9SEED"))
        .with_transport(transport.clone())
        .with_psk(pskid, psk)
        .build()?;

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce().await?;
        println!("  msg => <{}> {:x}", msg.msgid, msg.to_msg_index());
        print!("  Author     : {}", author);
        msg
    };

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
            ApplicationInstanceAnnouncementMismatch(String::from("C"))
        )?;
    }

    author.store_psk(pskid, psk)?;

    // Fetch state of subscriber for comparison after reset
    let sub_a_start_state: HashMap<_, _> = subscriberA.fetch_state()?.into_iter().collect();

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Subscribe A");
    {
        author.receive_subscribe(&subscribeA_link).await?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, PSK]");
    let (keyload_link, keyload_seq) = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!(
        "\nHandle Share keyload for everyone [SubscriberA, PSK]: {}",
        &keyload_link
    );
    {
        let msg_tag = subscriberA.receive_sequence(&keyload_seq).await?;
        let resultB = subscriberB.receive_keyload(&msg_tag).await?;
        print!("  SubscriberB: {}", subscriberB);
        try_or!(!resultB, SubscriberAccessMismatch(String::from("B")))?;

        subscriberA.receive_keyload(&msg_tag).await?;
        print!("  SubscriberA: {}", subscriberA);

        subscriberC.receive_keyload(&msg_tag).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    println!("\nSubscriber A fetching transactions...");
    utils::fetch_next_messages(&mut subscriberA).await?;

    println!("\nTagged packet 1 - SubscriberA");
    let (tagged_packet_link, tagged_packet_seq) = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        (msg, seq)
    };

    println!("\nHandle Tagged packet 1 - SubscriberA");
    {
        let msg_tag = author.receive_sequence(&tagged_packet_seq).await?;
        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&msg_tag).await?;
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (unwrapped_public, unwrapped_masked) = subscriberC.receive_tagged_packet(&msg_tag).await?;
        print!("  SubscriberC: {}", subscriberC);
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
    }

    println!("\nAuthor fetching transactions...");
    utils::fetch_next_messages(&mut author).await?;

    println!("\nSigned packet");
    let (_signed_packet_link, signed_packet_seq) = {
        let (msg, seq) = author
            .send_signed_packet(&tagged_packet_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!("\nHandle Signed packet");
    {
        let msg_tag = subscriberA.receive_sequence(&signed_packet_seq).await?;
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&msg_tag).await?;
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

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let (keyload_link, keyload_seq) = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!("\nHandle Share keyload for everyone [SubscriberA, SubscriberB]");
    {
        let msg_tag = subscriberA.receive_sequence(&keyload_seq).await?;
        print!("  Author     : {}", author);

        subscriberA.receive_keyload(&msg_tag).await?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_keyload(&msg_tag).await?;
        print!("  SubscriberB: {}", subscriberB);
        subscriberC.receive_keyload(&msg_tag).await?;
        print!("  SubscriberC: {}", subscriberC);
    }

    println!("\nSubscriber A fetching transactions...");
    utils::fetch_next_messages(&mut subscriberA).await?;

    println!("\nTagged packet 2 - SubscriberA");
    let (tagged_packet_link, tagged_packet_seq) = {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberA: {}", subscriberA);
        (msg, seq)
    };

    println!("\nHandle Tagged packet 2 - SubscriberA");
    {
        let msg_tag = author.receive_sequence(&tagged_packet_seq).await?;
        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&msg_tag).await?;
        print!("  Author     : {}", author);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;

        let (unwrapped_public, unwrapped_masked) = subscriberC.receive_tagged_packet(&msg_tag).await?;
        print!("  SubscriberC     : {}", subscriberC);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nSubscriber B fetching transactions...");
    utils::fetch_next_messages(&mut subscriberB).await?;

    println!("\nTagged packet 3 - SubscriberB");
    let (tagged_packet_link, tagged_packet_seq) = {
        let (msg, seq) = subscriberB
            .send_tagged_packet(&tagged_packet_link, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  SubscriberB: {}", subscriberB);
        (msg, seq)
    };

    println!("\nHandle Tagged packet 3 - SubscriberB");
    {
        let msg_tag = subscriberA.receive_sequence(&tagged_packet_seq).await?;
        let (unwrapped_public, unwrapped_masked) = subscriberA.receive_tagged_packet(&msg_tag).await?;
        print!("  SubscriberA: {}", subscriberA);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let (unwrapped_public, unwrapped_masked) = subscriberC.receive_tagged_packet(&msg_tag).await?;
        print!("  SubscriberC: {}", subscriberC);
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nSubscriber C fetching transactions...");
    utils::fetch_next_messages(&mut subscriberC).await?;

    // TODO: reintegrate this part of the example once Idenityless Users are reintroduced
    /*println!("\nAttempt Tagged packet 4 - SubscriberC");
    let tp = subscriberC
        .send_tagged_packet(&tagged_packet_link, &public_payload, &masked_payload)
        .await;
    assert!(
        tp.is_err(),
        "Subscriber C is a PSK user and should not be able to send messages"
    );
    println!("SubscriberC was not able to send tagged packet, as expected");
    */
    println!("\nAuthor fetching transactions...");
    utils::fetch_next_messages(&mut author).await?;

    println!("\nSigned packet");
    let (signed_packet_link, signed_packet_seq) = {
        let (msg, seq) = author
            .send_signed_packet(&tagged_packet_seq, &public_payload, &masked_payload)
            .await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        print!("  Author     : {}", author);
        (msg, seq)
    };

    println!("\nHandle Signed packet");
    {
        let msg_tag = subscriberA.receive_sequence(&signed_packet_seq).await?;
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&msg_tag).await?;
        print!("  SubscriberA: {}", subscriberA);

        println!("\nSubscriber A fetching transactions...");
        utils::fetch_next_messages(&mut subscriberA).await?;
        println!("\nSubscriber B fetching transactions...");
        utils::fetch_next_messages(&mut subscriberB).await?;

        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            masked_payload == unwrapped_masked,
            MaskedPayloadMismatch(masked_payload.to_string(), unwrapped_masked.to_string())
        )?;
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberB.receive_signed_packet(&msg_tag).await?;
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

    println!("\nSubscriber A checking previous message");
    {
        let msg = subscriberA.fetch_prev_msg(&signed_packet_link).await?;
        println!("Found message: {}", msg.link.msgid);
        try_or!(
            msg.link == tagged_packet_link,
            LinkMismatch(msg.link.msgid.to_string(), tagged_packet_link.msgid.to_string())
        )?;
        println!("  SubscriberA: {}", subscriberA);
    }

    println!("\nSubscriber A checking 3 previous messages");
    {
        let msgs = subscriberA.fetch_prev_msgs(&signed_packet_link, 3).await?;
        try_or!(msgs.len() == 3, ValueMismatch(3, msgs.len()))?;
        println!("Found {} messages", msgs.len());
        println!("  SubscriberB: {}", subscriberA);
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
    author.remove_subscriber(*subscriberA.id())?;

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
