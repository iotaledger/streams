// Rust

// IOTA

// Streams
use streams::{
    id::{Ed25519, Psk},
    Result, Selector, User,
};

// Local
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";

const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";

pub(crate) async fn example<SR, T: GenericTransport<SR>>(transport: T, author_seed: &str) -> Result<()> {
    let psk = Psk::from_seed("A pre shared key");

    let mut author = User::builder()
        .with_identity(Ed25519::from_seed(author_seed))
        .with_transport(transport.clone())
        .with_psk(psk.to_pskid(), psk)
        .build();

    let mut subscriber_a = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERA9SEED"))
        .with_transport(transport.clone())
        .build();

    let mut subscriber_b = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERB9SEED"))
        .with_transport(transport.clone())
        .build();

    let announcement = author.create_stream(BASE_BRANCH).await?;
    author.new_branch(BASE_BRANCH, BRANCH1).await?;

    // Subscribe A
    subscriber_a.receive_message(announcement.address()).await?;
    let subscription = subscriber_a.subscribe().await?;
    author.receive_message(subscription.address()).await?;

    author.send_keyload_for_all_rw(BRANCH1).await?;
    subscriber_a.sync().await?;
    subscriber_a
        .send_signed_packet(BRANCH1, &PUBLIC_PAYLOAD, &MASKED_PAYLOAD)
        .await?;
    subscriber_a
        .send_signed_packet(BRANCH1, &PUBLIC_PAYLOAD, &MASKED_PAYLOAD)
        .await?;

    // Subscribe B
    subscriber_b.receive_message(announcement.address()).await?;
    let subscription = subscriber_b.subscribe().await?;
    author.receive_message(subscription.address()).await?;
    author.send_keyload_for_all_rw(BRANCH1).await?;

    let selectors = vec![Selector::Topic(BRANCH1.into())];
    let msgs = subscriber_b.messages().from(&selectors).await;

    // Find the 2 messages from BRANCH1 (although unencryptable)
    assert!(msgs.len() == 2);

    author.sync().await?;
    subscriber_a.sync().await?;

    subscriber_a
        .send_signed_packet(BRANCH1, &PUBLIC_PAYLOAD, &MASKED_PAYLOAD)
        .await?;
    author
        .send_signed_packet(BRANCH1, &PUBLIC_PAYLOAD, &MASKED_PAYLOAD)
        .await?;

    let selectors = vec![Selector::Identifier(subscriber_a.identifier().unwrap().clone())];
    let msgs = subscriber_b.messages().from(&selectors).await;

    // Find only 1 message from Sub a, not the author message
    assert!(msgs.len() == 1);

    Ok(())
}
