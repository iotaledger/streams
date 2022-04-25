use anyhow::anyhow;
use identity::{
    core::Timestamp,
    did::MethodScope,
    iota::IotaVerificationMethod,
    prelude::{
        Client as DIDClient,
        IotaDocument,
        KeyPair as DIDKeyPair,
    },
};
use iota_streams::{
    app::{
        id::{
            DIDInfo,
            UserIdentity,
        },
        transport::tangle::client::Client,
    },
    app_channels::{
        api::{
            psk_from_seed,
            pskid_from_psk,
            tangle::UserBuilder,
        },
        Address,
    },
    core::{
        println,
        try_or,
        Errors::*,
        Result,
    },
    ddml::types::*,
};

use super::utils;

async fn make_did_info(client: &DIDClient, fragment: &str) -> Result<DIDInfo> {
    // Create Keypair to act as base of identity
    let keypair = DIDKeyPair::new_ed25519()?;
    // Generate original DID document
    let mut document = IotaDocument::new(&keypair)?;
    // Sign document and publish to the tangle
    document.sign_self(keypair.private(), document.default_signing_method()?.id().clone())?;
    let receipt = client.publish_document(&document).await?;
    let did = document.id().clone();
    println!("Document published: {}", receipt.message_id());

    println!("Creating new method...");
    let streams_method_keys = DIDKeyPair::new_ed25519()?;
    let method = IotaVerificationMethod::new(
        did.clone(),
        streams_method_keys.type_(),
        streams_method_keys.public(),
        fragment,
    )?;
    if document.insert_method(method, MethodScope::VerificationMethod).is_ok() {
        document.metadata.previous_message_id = *receipt.message_id();
        document.metadata.updated = Timestamp::now_utc();
        document.sign_self(keypair.private(), document.default_signing_method()?.id().clone())?;

        let update_receipt = client.publish_document(&document).await?;
        println!("Document updated: {}", update_receipt.message_id());
    } else {
        return Err(anyhow!("Failed to update method"));
    }

    Ok(DIDInfo {
        did: Some(did),
        key_fragment: fragment.to_string(),
        did_keypair: streams_method_keys,
    })
}

pub async fn example(transport: Client) -> Result<()> {
    println!("Creating new DID instance...");

    let (did_info, sub_did_info) = match transport.to_did_client() {
        Ok(client) => {
            println!("Making DID with method for Author");
            let did_info = make_did_info(&client, "auth_key").await?;
            println!("\nMaking another DID with method for a Subscriber");
            let sub_did_info = make_did_info(&client, "sub_key").await?;
            (did_info, sub_did_info)
        }
        Err(e) => return Err(anyhow!("DID Client could not be created from transport: {}", e)),
    };

    // Generate a simple PSK for storage by users
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);

    println!("Making Author...");
    let mut author_id = UserIdentity::new_with_did_private_key(did_info)?;
    author_id.insert_did_client(transport.clone().to_did_client()?);
    let mut author = UserBuilder::new()
        .with_identity(author_id)
        .with_transport(transport.clone())
        .build()?;

    println!("Making Subscribers...");
    let subscriberA_id = UserIdentity::new_with_did_private_key(sub_did_info)?;
    let mut subscriberA = UserBuilder::new()
        .with_identity(subscriberA_id)
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

    let subA_xkey = subscriberA.key_exchange_public_key()?;

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
    subscriberB.receive_announcement(&announcement_link).await?;
    subscriberC.receive_announcement(&announcement_link).await?;

    // Predefine Subscriber A
    println!("\nAuthor Predefines Subscriber A and Psk");
    author.store_new_subscriber(*subscriberA.id(), subA_xkey)?;

    // Generate a simple PSK for storage by users
    let psk = psk_from_seed("A pre shared key".as_bytes());
    let pskid = pskid_from_psk(&psk);
    author.store_psk(pskid, psk)?;

    println!("\nShare keyload for [SubscriberA, PSK]");
    let (keyload_link, keyload_seq) = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
        let seq = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq.msgid, seq.to_msg_index());
        (msg, seq)
    };

    println!(
        "\nHandle Share keyload for everyone [SubscriberA, PSK]: {}",
        &keyload_link
    );
    let msg_tag = subscriberA.receive_sequence(&keyload_seq).await?;
    let resultB = subscriberB.receive_keyload(&msg_tag).await?;
    try_or!(!resultB, SubscriberAccessMismatch(String::from("B")))?;

    subscriberA.receive_keyload(&msg_tag).await?;
    subscriberC.receive_keyload(&msg_tag).await?;

    println!("\nTagged packets - SubscriberA");
    let mut prev_link = keyload_link;
    let mut seq_link: Address;
    for _ in 0..5 {
        let (msg, seq) = subscriberA
            .send_tagged_packet(&prev_link, &public_payload, &masked_payload)
            .await?;
        seq_link = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq_link.msgid, seq_link.to_msg_index());
        prev_link = msg;
    }

    println!("\nAuthor fetching transactions...");
    utils::fetch_next_messages(&mut author).await?;

    println!("\nSigned packets - Author");
    for _ in 0..5 {
        let (msg, seq) = author
            .send_signed_packet(&prev_link, &public_payload, &masked_payload)
            .await?;
        seq_link = seq.unwrap();
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq_link.msgid, seq_link.to_msg_index());
        prev_link = msg;
    }

    println!("\nAuthor fetching transactions...");
    utils::fetch_next_messages(&mut subscriberC).await?;

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link).await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };

    println!("\nHandle Subscribe B");
    {
        author.receive_subscribe(&subscribeB_link).await?;
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB, PSK]");
    let (msg, seq) = author.send_keyload_for_everyone(&announcement_link).await?;
    seq_link = seq.unwrap();
    println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
    println!("  seq => <{}> <{:x}>", seq_link.msgid, seq_link.to_msg_index());
    prev_link = msg;

    println!("\nSubscriber A fetching transactions...");
    utils::fetch_next_messages(&mut subscriberA).await?;
    println!("\nSubscriber B fetching transactions...");
    utils::fetch_next_messages(&mut subscriberB).await?;
    println!("\nSubscriber C fetching transactions...");
    utils::fetch_next_messages(&mut subscriberC).await?;

    println!("\nTagged packets - SubscriberB");

    for _ in 0..5 {
        let (msg, _seq) = subscriberB
            .send_tagged_packet(&prev_link, &public_payload, &masked_payload)
            .await?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        println!("  seq => <{}> <{:x}>", seq_link.msgid, seq_link.to_msg_index());
        prev_link = msg;
    }

    println!("\nSubscriber A fetching transactions...");
    utils::fetch_next_messages(&mut subscriberA).await?;
    println!("\nSubscriber C fetching transactions...");
    utils::fetch_next_messages(&mut subscriberC).await?;
    println!("\nAuthor fetching transactions...");
    utils::fetch_next_messages(&mut author).await?;

    println!("\nSigned packet");
    let (msg, seq) = author
        .send_signed_packet(&prev_link, &public_payload, &masked_payload)
        .await?;
    seq_link = seq.unwrap();
    println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
    println!("  seq => <{}> <{:x}>", seq_link.msgid, seq_link.to_msg_index());

    Ok(())
}
