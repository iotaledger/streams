use iota_streams::{
    app::{
        message::HasLink,
        transport::tangle::PAYLOAD_BYTES,
    },
    app_channels::{
        api::tangle::{
            Author,
            Subscriber,
            Transport,
            user::UserImp,
            User,
            UserType,
        },
    },
    core::{
        prelude::Rc,
        print,
        println,
    },
    ddml::types::*,
};

use core::cell::RefCell;

use anyhow::{
    ensure,
    Result,
};

use super::utils;

pub fn example<T: Transport>(
    transport: Rc<RefCell<T>>,
    send_opt: T::SendOptions,
    recv_opt: T::RecvOptions,
    multi_branching: bool,
    seed: &str,
) -> Result<()>
where
    T::SendOptions: Copy + Default,
    T::RecvOptions: Copy + Default,
{
    let encoding = "utf-8";
    let author_imp = Author::new(seed, encoding, PAYLOAD_BYTES, multi_branching);
    println!("Author multi branching?: {}", author_imp.is_multi_branching());

    let subA = Subscriber::new("SUBSCRIBERA9SEED", encoding, PAYLOAD_BYTES);
    let subB = Subscriber::new("SUBSCRIBERB9SEED", encoding, PAYLOAD_BYTES);
    let subC = Subscriber::new("SUBSCRIBERC9SEED", encoding, PAYLOAD_BYTES);

    let mut author = User { user: author_imp, transport: transport.clone(), _recv_opt: recv_opt, _send_opt: send_opt, user_type: UserType::Author };
    let mut subscriberA = User { user: subA, transport: transport.clone(), _recv_opt: recv_opt, _send_opt: send_opt, user_type: UserType::Subscriber };
    let mut subscriberB = User { user: subB, transport: transport.clone(), _recv_opt: recv_opt, _send_opt: send_opt, user_type: UserType::Subscriber };
    let mut subscriberC = User { user: subC, transport: transport.clone(), _recv_opt: recv_opt, _send_opt: send_opt, user_type: UserType::Subscriber };

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce()?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  Author     : {}", author.user);
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    {
        subscriberA.receive_announcement(&announcement_link)?;
        print!("  SubscriberA: {}", subscriberA.user);
        ensure!(
            (author.channel_address() == subscriberA.channel_address()),
            "SubscriberA channel address does not match Author channel address"
        );
        subscriberB.receive_announcement(&announcement_link)?;
        print!("  SubscriberB: {}", subscriberB.user);
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "SubscriberB channel address does not match Author channel address"
        );
        subscriberC.receive_announcement(&announcement_link)?;
        print!("  SubscriberC: {}", subscriberC.user);
        ensure!(
            subscriberA.channel_address() == subscriberC.channel_address(),
            "SubscriberC channel address does not match Author channel address"
        );

        ensure!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            "SubscriberA app instance does not match announcement link base"
        );
        ensure!(
            subscriberA.is_multi_branching() == author.is_multi_branching(),
            "Subscribers should have the same branching flag as the author after unwrapping"
        );
    }

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberA: {}", subscriberA.user);
        msg
    };

    println!("\nHandle Subscribe A");
    {
        author.receive_subscribe(&subscribeA_link)?;
        print!("  Author     : {}", author.user);
    }

    println!("\nSubscribe B");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        print!("  SubscriberB: {}", subscriberB.user);
        msg
    };

    println!("\nHandle Subscribe B");
    {
        author.receive_subscribe(&subscribeB_link)?;
        print!("  Author     : {}", author.user);
    }

    println!("\nShare keyload for everyone [SubscriberA, SubscriberB]");
    let previous_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author.user);
        msg
    };

    println!("\nHandle Keyload");
    {
        let resultC = subscriberC.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberC: {}", subscriberC.user);
        ensure!(resultC == false, "SubscriberC should not be able to unwrap the keyload");

        subscriberA.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA.user);
        subscriberB.receive_keyload(&previous_msg_link)?;
        print!("  SubscriberB: {}", subscriberB.user);
    }

    println!("\nSigned packet");
    let previous_msg_link = {
        print!("  Author     : {}", author.user);
        let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author.user);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA.user);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    println!("\nSubscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA);

    println!("\nTagged packet 1 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA.user);
        msg
    };

    println!("\nHandle Tagged packet 1");
    {
        let (unwrapped_public, unwrapped_masked) = author.receive_tagged_packet(&previous_msg_link)?;
        print!("  Author     : {}", author.user);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.receive_tagged_packet(&previous_msg_link);
        print!("  SubscriberC: {}", subscriberC.user);
        ensure!(
            resultC.is_err(),
            "Subscriber C should not be able to access this message"
        );
    }

    println!("\nTagged packet 2 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA.user);
        msg
    };

    println!("\nTagged packet 3 - SubscriberA");
    let previous_msg_link = {
        let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberA: {}", subscriberA.user);
        msg
    };

    println!("\nSubscriber B fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberB);

    println!("\nTagged packet 4 - SubscriberB");
    let previous_msg_link = {
        let (msg, seq) = subscriberB.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  SubscriberB: {}", subscriberB.user);
        msg
    };

    println!("\nHandle Tagged packet 4");
    {
        let (unwrapped_public, unwrapped_masked) = subscriberA.receive_tagged_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA.user);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let resultC = subscriberC.receive_tagged_packet(&previous_msg_link);
        print!("  SubscriberC: {}", subscriberC.user);
        ensure!(
            resultC.is_err(),
            "Subscriber C should not be able to access this message"
        );
    }

    println!("\nAuthor fetching transactions...");
    utils::a_fetch_next_messages(&mut author);

    println!("\nSigned packet");
    let previous_msg_link = {
        let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
        println!("  msg => <{}> {:?}", msg.msgid, msg);
        assert!(seq.is_none());
        print!("  Author     : {}", author.user);
        msg
    };

    println!("\nHandle Signed packet");
    {
        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberA: {}", subscriberA.user);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");

        let (_signer_pk, unwrapped_public, unwrapped_masked) = subscriberB.receive_signed_packet(&previous_msg_link)?;
        print!("  SubscriberB: {}", subscriberB.user);
        ensure!(public_payload == unwrapped_public, "Public payloads do not match");
        ensure!(masked_payload == unwrapped_masked, "Masked payloads do not match");
    }

    Ok(())
}
