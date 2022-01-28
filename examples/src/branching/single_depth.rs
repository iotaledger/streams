use iota_streams::{
    app::message::HasLink,
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::{
            Author,
            ChannelType,
            MessageContent,
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

pub async fn example<T: Transport>(transport: T, channel_impl: ChannelType, seed: &str) -> Result<()> {
    let mut author = Author::new(seed, channel_impl, transport.clone());
    println!("Author single depth?: {}", author.is_single_depth());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone());
    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", transport.clone());
    let mut subscriberC = Subscriber::new("SUBSCRIBERC9SEED", transport);

    let empty_payload = Bytes(Vec::new());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce().await?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        print!("  Author     : {}", author);
        msg
    };
    println!("Author channel address: {}", author.channel_address().unwrap());

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

        try_or!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            ApplicationInstanceMismatch(String::from("A"))
        )?;
        try_or!(
            subscriberA.is_single_depth() == author.is_single_depth(),
            BranchingFlagMismatch(String::from("A"))
        )?;
    }

    // Generate a simple PSK for storage by users
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);
    author.store_psk(pskid, psk)?;
    subscriberB.store_psk(pskid, psk)?;

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link).await?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        print!("  SubscriberA: {}", subscriberA);
        msg
    };

    println!("\nHandle Subscribe A");
    {
        author.receive_subscribe(&subscribeA_link).await?;
        print!("  Author     : {}", author);
    }

    println!("\nShare keyload for everyone [SubscriberA, PSK]");
    let anchor_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        println!("  msg => <{}> {}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author);
        msg
    };

    println!("\nHandle Keyload");
    {
        subscriberA.receive_keyload(&anchor_msg_link).await?;
        print!("  SubscriberA: {}", subscriberA);
        subscriberB.receive_keyload(&anchor_msg_link).await?;
        print!("  SubscriberB: {}", subscriberB);
    }

    println!("\n Sending messages for subscribers");
    for i in 0..10 {
        let mut message = String::from("Message ");
        message.push_str(&i.to_string());
        let masked_payload = Bytes(message.as_bytes().to_vec());
        let (msg, seq) = author
            .send_signed_packet(&anchor_msg_link, &empty_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> {}", msg.msgid, msg.to_msg_index());
        assert!(seq.is_none());
    }
    print!("  Author     : {}", author);

    println!("\nSubscriber A fetching all messages");
    let mut unwrapped = Vec::new();
    loop {
        let msgs = subscriberA.fetch_next_msgs().await;
        if msgs.is_empty() {
            break;
        }
        unwrapped.extend(msgs);
    }

    assert_eq!(unwrapped.len(), 10);
    for msg in unwrapped {
        if let MessageContent::SignedPacket {
            id: _,
            public_payload: _,
            masked_payload,
        } = &msg.body
        {
            println!(
                "  Msg => <{}>: {}",
                msg.link.msgid,
                String::from_utf8(masked_payload.0.to_vec()).unwrap()
            );
        } else {
            panic!("Packet found was not a signed packet from author")
        }
    }
    print!(" SubscriberA     : {}", subscriberA);

    println!("\nSubscriber B fetching 4th message");
    let msg = subscriberB.receive_msg_by_sequence_number(&anchor_msg_link, 4).await?;
    if let MessageContent::SignedPacket {
        id: _,
        public_payload: _,
        masked_payload,
    } = &msg.body
    {
        println!(
            "  Msg => <{}>: {}",
            msg.link.msgid,
            String::from_utf8(masked_payload.0.to_vec()).unwrap()
        );
        assert_eq!(masked_payload.0, "Message 4".as_bytes().to_vec());
    } else {
        panic!("Packet found was not a signed packet from author")
    }

    println!("\nSubscriber C trying to fetch 4th message");
    let msg = subscriberC.receive_msg_by_sequence_number(&anchor_msg_link, 4).await;
    try_or!(msg.is_err(), SubscriberAccessMismatch("C".to_string()))?;
    println!("Subscriber C failed to read message, as intended\n");
    Ok(())
}
