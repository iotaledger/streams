// Rust

// 3rd-party
use anyhow::{
    ensure,
    Result,
};
use futures::TryStreamExt;
use textwrap::indent;

// IOTA

// Streams
use iota_streams::{
    id::{
        Ed25519,
        Identity,
        Psk,
    },
    Address,
    Message,
    User,
};
use spongos::KeccakF1600;

// Local
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";

pub(crate) async fn example<T: GenericTransport>(transport: T, seed: &str) -> Result<()> {
    // Generate a simple PSK for storage by users
    let psk = Psk::new::<KeccakF1600, _>("A pre shared key");

    let mut author = User::builder()
        .with_identity(Identity::Ed25519(Ed25519::from_seed::<KeccakF1600, _>(seed)))
        .with_transport(transport.clone())
        .build()?;

    let mut subscriberA = User::builder()
        .with_identity(Identity::Ed25519(Ed25519::from_seed::<KeccakF1600, _>(
            "SUBSCRIBERA9SEED",
        )))
        .with_transport(transport.clone())
        .build()?;
    let mut subscriberB = User::builder()
        .with_identity(Identity::Ed25519(Ed25519::from_seed::<KeccakF1600, _>(
            "SUBSCRIBERB9SEED",
        )))
        .with_transport(transport.clone())
        .build()?;
    let mut subscriberC = User::builder()
        .with_identity(Identity::Psk(psk))
        .with_transport(transport.clone())
        .build()?;

    println!("> Author creates stream and sends its announcement");
    author.create_stream(8)?;
    let announcement = author.announce().await?;
    println!(
        "  msg => <{}> [{}]",
        announcement.address().relative(),
        hex::encode(announcement.address().to_msg_index())
    );
    print_user("Author", &author);

    println!("> Subscribers read the announcement to connect to the stream");
    subscriberA.receive_message(*announcement.address()).await?;
    print_user("Subscriber A", &subscriberA);
    subscriberB.receive_message(*announcement.address()).await?;
    print_user("Subscriber B", &subscriberB);
    subscriberC.receive_message(*announcement.address()).await?;
    print_user("Subscriber C", &subscriberC);

    author.store_psk(psk);

    println!("> Subscriber A sends subscription");
    let subscription_a_as_a = subscriberA.subscribe(announcement.address().relative()).await?;
    println!(
        "  msg => <{}> [{}]",
        subscription_a_as_a.address().relative(),
        hex::encode(subscription_a_as_a.address().to_msg_index())
    );
    print_user("Subscriber A", &subscriberA);

    println!("> Author reads subscription of subscriber A");
    let subscription_a_as_author = author.receive_message(*subscription_a_as_a.address()).await?;
    print_user("Author", &author);

    println!("> Author issues keyload for every user subscribed so far [SubscriberA, PSK]");
    let keyload_as_author = author.send_keyload_for_all(announcement.address().relative()).await?;
    println!(
        "  msg => <{}> [{}]",
        keyload_as_author.address().relative(),
        hex::encode(keyload_as_author.address().to_msg_index())
    );
    print_user("Author", &author);

    println!("> Subscribers read the keyload");
    let keyload_as_a = subscriberA
        .messages()
        .try_next()
        .await?
        .expect("subscriber A did not receive the expected keyload");
    print_user("Subscriber A", &subscriberA);
    assert!(keyload_as_a
        .as_keyload()
        .expect("expected keyload, found something else")
        .includes(subscriberA.identifier()));
    let keyload_as_b = subscriberB
        .messages()
        .try_next()
        .await?
        .expect("subscriber B did not receive the expected keyload");
    print_user("Subscriber B", &subscriberB);
    assert!(!keyload_as_b
        .as_keyload()
        .expect("expected keyload, found something else")
        .includes(subscriberB.identifier()));
    let keyload_as_c = subscriberC
        .messages()
        .try_next()
        .await?
        .expect("subscriber C did not receive the expected keyload");
    print_user("Subscriber C", &subscriberC);
    assert!(keyload_as_c
        .as_keyload()
        .expect("expected keyload, found something else")
        .includes(subscriberC.identifier()));

    println!("> Subscriber A sends a tagged packet linked to the keyload");
    let tagged_packet_as_a = subscriberA
        .send_tagged_packet(keyload_as_a.address().relative(), PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    println!(
        "  msg => <{}> [{}]",
        tagged_packet_as_a.address().relative(),
        hex::encode(tagged_packet_as_a.address().to_msg_index())
    );
    print_user("Subscriber A", &subscriberA);

    println!("> Author receives the tagged packet");
    let tagged_packet_as_author = author
        .messages()
        .try_next()
        .await?
        .expect("author did not receive the tagged packet sent by subscriber A");
    print_user("Author", &author);
    assert_eq!(
        tagged_packet_as_author
            .public_payload()
            .expect("expected a message with public payload, found something else"),
        PUBLIC_PAYLOAD
    );
    assert_eq!(
        tagged_packet_as_author
            .masked_payload()
            .expect("expected a message with masked payload, found something else"),
        MASKED_PAYLOAD
    );

    println!("> Subscriber C receives the tagged packet (because of the PSK)");
    let tagged_packet_as_c = subscriberC
        .messages()
        .try_next()
        .await?
        .expect("subscriber C did not receive the tagged packet sent by subscriber A");
    print_user("Subscriber C", &subscriberC);
    assert_eq!(
        tagged_packet_as_c
            .public_payload()
            .expect("expected a message with public payload, found something else"),
        PUBLIC_PAYLOAD
    );
    assert_eq!(
        tagged_packet_as_c
            .masked_payload()
            .expect("expected a message with masked payload, found something else"),
        MASKED_PAYLOAD
    );

    println!("> Subscriber B cannot receive the tagged packet (because hasn't subscribed yet)");
    let tagged_packet_as_b = subscriberB.messages().try_next().await?;
    print_user("Subscriber B", &subscriberB);
    assert!(tagged_packet_as_b.is_none());

    println!("> Subscriber B sends subscription");
    let subscription_b = subscriberB.subscribe(announcement.address().relative()).await?;
    println!(
        "  msg => <{}> [{}]",
        subscription_b.address().relative(),
        hex::encode(subscription_b.address().to_msg_index())
    );
    print_user("Subscriber B", &subscriberB);

    println!("> Author reads subscription of subscriber B");
    author.receive_message(*subscription_b.address()).await?;
    print_user("Author", &author);

    println!("> Author issues new keyload in the same branch to incorporate SubscriberB");
    let new_keyload_as_author = author
        .send_keyload_for_all(tagged_packet_as_author.address().relative())
        .await?;
    println!(
        "  msg => <{}> [{}]",
        new_keyload_as_author.address().relative(),
        hex::encode(new_keyload_as_author.address().to_msg_index())
    );
    print_user("Author", &author);

    println!("> Author sends a signed packet");
    let signed_packet_as_author = author
        .send_signed_packet(
            new_keyload_as_author.address().relative(),
            PUBLIC_PAYLOAD,
            MASKED_PAYLOAD,
        )
        .await?;
    println!(
        "  msg => <{}> [{}]",
        signed_packet_as_author.address().relative(),
        hex::encode(signed_packet_as_author.address().to_msg_index())
    );
    print_user("Author", &author);

    println!("> Subscriber B reads the pending messages [last-keyload, signed-packet]");
    let next_messages = subscriberB.fetch_next_messages().await?;
    let (new_keyload_as_b, signed_packet_as_b) = (&next_messages[0], &next_messages[1]);
    println!("  SubscriberB:\n{:?}", subscriberB);
    assert_eq!(
        signed_packet_as_b
            .public_payload()
            .expect("expected a message with public payload, found something else"),
        PUBLIC_PAYLOAD
    );
    assert_eq!(
        signed_packet_as_b
            .masked_payload()
            .expect("expected a message with masked payload, found something else"),
        MASKED_PAYLOAD
    );

    println!("> Subscriber C attempts to send a packet (but PSK users cannot send packets!)");
    let messages_in_branch_as_c = subscriberC
        .messages()
        .filter_branch(|message| {
            futures::future::ok({
                let linked_msg = message
                    .header()
                    .linked_msg_address()
                    .expect("all messages except announcement should have a linked message");
                linked_msg == tagged_packet_as_c.address().relative()
            })
        })
        .try_collect::<Vec<Message<Address>>>()
        .await?;
    let last_message_in_branch_as_c = messages_in_branch_as_c
        .last()
        .expect("Subscriber C hasn't received any of the new messages");
    let result = subscriberC
        .send_tagged_packet(
            last_message_in_branch_as_c.address().relative(),
            PUBLIC_PAYLOAD,
            MASKED_PAYLOAD,
        )
        .await;
    assert!(
        result.is_err(),
        "Subscriber C is a PSK user and should not be able to send messages"
    );
    println!("> SubscriberC was not able to send tagged packet, as expected");

    println!("> Author unsubscribes Subscriber A");
    author.remove_subscriber(
        subscription_a_as_author
            .as_subscription()
            .expect("message is supposed to be a subscription")
            .subscriber_identifier(),
    );

    println!("> Subscriber B sends unsubscription");
    let unsub_link = subscriberB.unsubscribe(new_keyload_as_b.address().relative()).await?;
    println!("Author receives unsubscription");
    author.sync_state().await?;

    println!("> Author removes PSK");
    author.remove_psk(psk.to_pskid::<KeccakF1600>());

    println!("> Author issues a new keyload to remove all subscribers from the branch");
    let last_keyload = author
        .send_keyload_for_all(new_keyload_as_author.address().relative())
        .await?;
    println!("> Author sends a new signed packet");
    author
        .send_signed_packet(last_keyload.address().relative(), PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;

    println!("> Subscriber A only receives the last keyload");
    let next_messages = subscriberA.fetch_next_messages().await?;
    let last_msg_as_a = next_messages
        .last()
        .expect("Subscriber A has not received the lattest keyload");
    assert!(last_msg_as_a.is_keyload());

    println!("> Subscriber B only receives the last keyload");
    let next_messages = subscriberB.fetch_next_messages().await?;
    let last_msg_as_b = next_messages
        .last()
        .expect("Subscriber B has not received the lattest keyload");
    assert!(last_msg_as_b.is_keyload());

    println!("> Subscriber C only receives the last keyload");
    let next_messages = subscriberC.fetch_next_messages().await?;
    let last_msg_as_c = next_messages
        .last()
        .expect("Subscriber B has not received the lattest keyload");
    assert!(last_msg_as_c.is_keyload());

    println!("> Subscribers A B and C try to send a signed packet");
    subscriberA
        .send_signed_packet(last_msg_as_a.address().relative(), PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    subscriberB
        .send_signed_packet(last_msg_as_b.address().relative(), PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    subscriberC
        .send_signed_packet(last_msg_as_c.address().relative(), PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;

    println!("> The message is not received by the rest of the subscribers");
    assert_eq!(author.sync_state().await?, 0);
    assert_eq!(subscriberA.sync_state().await?, 0);
    assert_eq!(subscriberB.sync_state().await?, 0);
    assert_eq!(subscriberC.sync_state().await?, 0);

    Ok(())
}

fn print_user<T, TSR>(user_name: &str, user: &User<T, TSR>) {
    println!("  {}:\n{}", user_name, indent(&format!("{:?}", user), "\t"));
}
