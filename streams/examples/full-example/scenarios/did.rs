// Rust

// 3rd-arty
use anyhow::anyhow;
use textwrap::{fill, indent};

// IOTA
use identity_iota::{
    core::Timestamp,
    crypto::KeyType,
    did::MethodScope,
    iota_core::IotaVerificationMethod,
    prelude::{Client as DIDClient, IotaDocument, KeyPair as DIDKeyPair},
};

// Streams
use streams::{
    id::{
        did::{DIDInfo, DIDUrlInfo, DID},
        Ed25519, Permissioned, Psk,
    },
    Result, User,
};

use super::utils::{print_send_result, print_user};
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";
const CLIENT_URL: &str = "https://chrysalis-nodes.iota.org";

const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";

pub(crate) async fn example<SR, T: GenericTransport<SR>>(transport: T) -> Result<()> {
    let did_client = DIDClient::builder()
        .primary_node(CLIENT_URL, None, None)
        .map_err(|e| anyhow!(e.to_string()))?
        .build()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    println!("> Making DID with method for the Author");
    let author_did_info = make_did_info(&did_client, "auth_key", "auth_xkey", "signing_key").await?;
    println!("> Making another DID with method for a Subscriber");
    let subscriber_did_info = make_did_info(&did_client, "sub_key", "sub_xkey", "signing_key").await?;

    // Generate a simple PSK for storage by users
    let psk = Psk::from_seed("A pre shared key");

    let mut author = User::builder()
        .with_identity(DID::PrivateKey(author_did_info))
        .with_transport(transport.clone())
        .with_psk(psk.to_pskid(), psk)
        .build();
    let mut subscriber_a = User::builder()
        .with_identity(DID::PrivateKey(subscriber_did_info))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_b = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERB9SEED"))
        .with_transport(transport.clone())
        .build();
    let mut subscriber_c = User::builder()
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();

    println!("> Author creates stream and sends its announcement");
    // Start at index 1, because we can. Will error if its already in use
    let announcement = author.create_stream(BASE_BRANCH).await?;
    print_send_result(&announcement);
    print_user("Author", &author);

    println!("> Subscribers read the announcement to connect to the stream");
    subscriber_a.receive_message(announcement.address()).await?;
    print_user("Subscriber A", &subscriber_a);
    subscriber_b.receive_message(announcement.address()).await?;
    print_user("Subscriber B", &subscriber_b);
    subscriber_c.receive_message(announcement.address()).await?;
    print_user("Subscriber C", &subscriber_c);

    // Predefine Subscriber A
    println!("> Subscribers A and B sends subscription");
    let subscription_a_as_a = subscriber_a.subscribe().await?;
    print_send_result(&subscription_a_as_a);
    print_user("Subscriber A", &subscriber_a);

    let subscription_b_as_b = subscriber_b.subscribe().await?;
    print_send_result(&subscription_b_as_b);
    print_user("Subscriber A", &subscriber_b);

    println!("> Author reads subscription of subscribers A and B");
    let _subscription_a_as_author = author.receive_message(subscription_a_as_a.address()).await?;
    let subscription_b_as_author = author.receive_message(subscription_b_as_b.address()).await?;
    print_user("Author", &author);

    println!("> Author creates new branch");
    let branch_announcement = author.new_branch(BASE_BRANCH, BRANCH1).await?;
    print_send_result(&branch_announcement);
    print_user("Author", &author);

    println!("> Author issues keyload for everybody [Subscriber A, Subscriber B, PSK]");
    let first_keyload_as_author = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&first_keyload_as_author);
    print_user("Author", &author);

    println!("> Author sends 3 signed packets linked to the keyload");
    for _ in 0..3 {
        let last_msg = author
            .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
            .await?;
        print_send_result(&last_msg);
    }
    print_user("Author", &author);

    println!("> Author issues new keyload for only Subscriber B and PSK");
    let second_keyload_as_author = author
        .send_keyload(
            BRANCH1,
            [Permissioned::Read(subscription_b_as_author.header().publisher())],
            [psk.to_pskid()],
        )
        .await?;
    print_send_result(&second_keyload_as_author);
    print_user("Author", &author);

    println!("> Author sends 2 more signed packets linked to the latest keyload");
    for _ in 0..2 {
        let last_msg = author
            .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
            .await?;
        print_send_result(&last_msg);
    }
    print_user("Author", &author);

    println!("> Author sends 1 more signed packet linked to the first keyload");
    let last_msg = author
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    print_send_result(&last_msg);
    print_user("Author", &author);

    println!("> Subscriber C receives 9 messages:");
    let messages_as_c = subscriber_c.fetch_next_messages().await?;
    print_user("Subscriber C", &subscriber_c);
    for message in &messages_as_c {
        println!("\t{}", message.address());
        println!("{}", indent(&fill(&format!("{:?}", message.content()), 140), "\t| "));
        println!("\t---");
    }
    assert_eq!(9, messages_as_c.len());

    println!("> Subscriber B receives 9 messages:");
    let messages_as_b = subscriber_b.fetch_next_messages().await?;
    print_user("Subscriber B", &subscriber_b);
    for message in &messages_as_c {
        println!("\t{}", message.address());
        println!("{}", indent(&fill(&format!("{:?}", message.content()), 140), "\t| "));
        println!("\t---");
    }
    assert_eq!(9, messages_as_b.len());

    println!("> Subscriber A receives 7 messages:");
    let messages_as_a = subscriber_a.fetch_next_messages().await?;
    print_user("Subscriber A", &subscriber_a);
    for message in &messages_as_a {
        println!("\t{}", message.address());
        println!("{}", indent(&fill(&format!("{:?}", message.content()), 140), "\t| "));
        println!("\t---");
    }
    assert_eq!(6, messages_as_a.len());

    Ok(())
}

async fn make_did_info(
    did_client: &DIDClient,
    signing_fragment: &str,
    exchange_fragment: &str,
    doc_signing_fragment: &str,
) -> anyhow::Result<DIDInfo> {
    // Create Keypair to act as base of identity
    let keypair = DIDKeyPair::new(KeyType::Ed25519)?;
    // Generate original DID document
    let mut document = IotaDocument::new_with_options(&keypair, None, Some(doc_signing_fragment))?;
    // Sign document and publish to the tangle
    document.sign_self(keypair.private(), doc_signing_fragment)?;
    let receipt = did_client.publish_document(&document).await?;
    let did = document.id().clone();

    // Create a signature verification keypair and method
    let streams_signing_keys = DIDKeyPair::new(KeyType::Ed25519)?;
    let method = IotaVerificationMethod::new(
        did.clone(),
        streams_signing_keys.type_(),
        streams_signing_keys.public(),
        signing_fragment,
    )?;

    // Create a second Keypair for key exchange method
    let streams_exchange_keys = DIDKeyPair::new(KeyType::X25519)?;
    let xmethod = IotaVerificationMethod::new(
        did.clone(),
        streams_exchange_keys.type_(),
        streams_exchange_keys.public(),
        exchange_fragment,
    )?;

    if document.insert_method(method, MethodScope::VerificationMethod).is_ok()
        && document.insert_method(xmethod, MethodScope::key_agreement()).is_ok()
    {
        document.metadata.previous_message_id = *receipt.message_id();
        document.metadata.updated = Some(Timestamp::now_utc());
        document.sign_self(keypair.private(), doc_signing_fragment)?;

        let _update_receipt = did_client.publish_document(&document).await?;
    } else {
        return Err(anyhow::anyhow!("Failed to update method"));
    }

    let url_info = DIDUrlInfo::new(did, CLIENT_URL, exchange_fragment, signing_fragment);
    Ok(DIDInfo::new(url_info, streams_signing_keys, streams_exchange_keys))
}
