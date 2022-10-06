// Rust

// 3rd-party
use futures::TryStreamExt;

// IOTA

// Streams
use streams::{
    id::{Ed25519, PermissionDuration, Permissioned, Psk},
    Result, User,
};

// Local
use super::utils::{print_send_result, print_user};
use crate::GenericTransport;

const PUBLIC_PAYLOAD: &[u8] = b"PUBLICPAYLOAD";
const MASKED_PAYLOAD: &[u8] = b"MASKEDPAYLOAD";

const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";
const BRANCH2: &str = "BRANCH2";

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
    let mut subscriber_c = User::builder()
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();

    // Confirm that users have id's
    let _author_id = author.identifier().expect("author should have identifier");
    let subscriber_a_id = subscriber_a
        .identifier()
        .expect("subscriber A should have identifier")
        .clone();
    let subscriber_b_id = subscriber_b
        .identifier()
        .expect("subscriber B should have identifier")
        .clone();
    assert!(subscriber_c.identifier().is_none());

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

    println!("> Subscriber A sends subscription");
    let subscription_a_as_a = subscriber_a.subscribe().await?;
    print_send_result(&subscription_a_as_a);
    print_user("Subscriber A", &subscriber_a);

    println!("> Author reads subscription of subscriber A");
    let subscription_a_as_author = author.receive_message(subscription_a_as_a.address()).await?;
    print_user("Author", &author);

    println!("> Author creates a new branch");
    println!("Branch topic: {}", BRANCH1);
    let branch_announcement = author.new_branch(BASE_BRANCH, BRANCH1).await?;
    print_send_result(&branch_announcement);
    print_user("Author", &author);

    println!("> Author issues keyload for every user subscribed so far [SubscriberA, PSK] in Branch 1");
    let keyload_as_author = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&keyload_as_author);
    print_user("Author", &author);

    println!("> Subscribers read branch announcement");
    let branch_1_ann_as_a = subscriber_a
        .messages()
        .try_next()
        .await?
        .expect("Subscriber A did not receive the expected branch announcement");
    assert!(
        branch_1_ann_as_a
            .as_branch_announcement()
            .expect("expected branch announcement, found something else")
            .topic
            .eq(&BRANCH1.into())
    );
    print_user("Subscriber A", &subscriber_a);
    let branch_1_ann_as_b = subscriber_b
        .messages()
        .try_next()
        .await?
        .expect("Subscriber B did not receive the expected branch announcement");
    assert!(
        branch_1_ann_as_b
            .as_branch_announcement()
            .expect("expected branch announcement, found something else")
            .topic
            .eq(&BRANCH1.into())
    );
    print_user("Subscriber B", &subscriber_b);
    let branch_1_ann_as_c = subscriber_c
        .messages()
        .try_next()
        .await?
        .expect("Subscriber C did not receive the expected branch announcement");
    assert!(
        branch_1_ann_as_c
            .as_branch_announcement()
            .expect("expected branch announcement, found something else")
            .topic
            .eq(&BRANCH1.into())
    );
    print_user("Subscriber C", &subscriber_c);

    println!("> Subscribers read the keyload");
    let keyload_as_a = subscriber_a
        .messages()
        .try_next()
        .await?
        .expect("subscriber A did not receive the expected keyload");
    print_user("Subscriber A", &subscriber_a);
    assert!(
        keyload_as_a
            .as_keyload()
            .expect("expected keyload, found something else")
            .includes_subscriber(&subscriber_a_id)
    );
    let keyload_as_b = subscriber_b
        .messages()
        .try_next()
        .await?
        .expect("subscriber B did not receive the expected keyload");
    print_user("Subscriber B", &subscriber_b);
    assert!(
        !keyload_as_b
            .as_keyload()
            .expect("expected keyload, found something else")
            .includes_subscriber(&subscriber_b_id)
    );
    let keyload_as_c = subscriber_c
        .messages()
        .try_next()
        .await?
        .expect("subscriber C did not receive the expected keyload");
    print_user("Subscriber C", &subscriber_c);
    assert!(
        keyload_as_c
            .as_keyload()
            .expect("expected keyload, found something else")
            .includes_psk(&psk.to_pskid())
    );

    println!("> Author sends a tagged packet linked to the keyload");
    let tagged_packet_as_author = author
        .message()
        .with_topic(BRANCH1)
        .with_payload(MASKED_PAYLOAD)
        .send()
        .await?;
    print_send_result(&tagged_packet_as_author);
    print_user("Author", &author);

    println!("> Subscriber A receives the tagged packet");
    let tagged_packet_as_a = subscriber_a
        .messages()
        .try_next()
        .await?
        .expect("subscriber A did not receive the tagged packet sent by Author");
    print_user("Subscriber A", &subscriber_a);
    assert!(
        tagged_packet_as_a
            .public_payload()
            .expect("expected a message with public payload, found something else")
            .is_empty()
    );
    assert_eq!(
        tagged_packet_as_a
            .masked_payload()
            .expect("expected a message with masked payload, found something else"),
        MASKED_PAYLOAD
    );

    println!("> Subscriber C receives the tagged packet (because of the PSK)");
    let tagged_packet_as_c = subscriber_c
        .messages()
        .try_next()
        .await?
        .expect("subscriber C did not receive the tagged packet sent by subscriber A");
    print_user("Subscriber C", &subscriber_c);
    assert!(
        tagged_packet_as_c
            .public_payload()
            .expect("expected a message with public payload, found something else")
            .is_empty()
    );
    assert_eq!(
        tagged_packet_as_c
            .masked_payload()
            .expect("expected a message with masked payload, found something else"),
        MASKED_PAYLOAD
    );

    println!("> Subscriber B cannot receive the tagged packet (because hasn't subscribed yet)");
    let tagged_packet_as_b = subscriber_b.messages().try_next().await?;
    print_user("Subscriber B", &subscriber_b);
    assert!(tagged_packet_as_b.is_none());

    println!("> Author manually subscribes subscriber B");
    author.add_subscriber(subscriber_b_id.clone());
    print_user("Author", &author);

    println!("> Author issues new keyload in the same branch to incorporate SubscriberB");
    let new_keyload_as_author = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&new_keyload_as_author);
    print_user("Author", &author);

    println!("> Author sends a signed packet");
    let signed_packet_as_author = author
        .message()
        .with_topic(BRANCH1)
        .with_payload(PUBLIC_PAYLOAD)
        .public()
        .send()
        .await?;
    print_send_result(&signed_packet_as_author);
    print_user("Author", &author);

    println!("> Subscriber B reads the pending messages [last-keyload, signed-packet]");
    let next_messages = subscriber_b.fetch_next_messages().await?;
    let (new_keyload_as_b, signed_packet_as_b) = (&next_messages[0], &next_messages[1]);
    print_user("Subscriber B", &subscriber_b);
    assert!(new_keyload_as_b.is_keyload());
    assert_eq!(
        signed_packet_as_b
            .public_payload()
            .expect("expected a message with public payload, found something else"),
        PUBLIC_PAYLOAD
    );
    assert!(
        signed_packet_as_b
            .masked_payload()
            .expect("expected a message with masked payload, found something else")
            .is_empty()
    );

    assert_eq!(author.sync().await?, 0);
    assert_eq!(subscriber_a.sync().await?, 2);
    assert_eq!(subscriber_b.sync().await?, 0);

    println!("> Subscriber C attempts to send a signed packet (but PSK users cannot send packets!)");
    let messages_in_branch_as_c = subscriber_c
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
        .try_collect::<Vec<_>>()
        .await?;
    messages_in_branch_as_c
        .last()
        .expect("Subscriber C hasn't received any of the new messages");
    let result = subscriber_c
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;
    assert!(
        result.is_err(),
        "Subscriber C is a PSK user and should not be able to send signed packets"
    );
    println!("> SubscriberC was not able to send signed packet, as expected");

    println!("> Subscriber A attempts to send a signed packet (but he has readonly permission over the branch!)");
    let result = subscriber_a
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;
    assert!(
        result.is_err(),
        "Subscriber A has readonly permissions and should not be able to send signed packets"
    );

    println!("> The other users don't receive the messages attempted by Subscriber C and Subscriber A");
    assert_eq!(author.sync().await?, 0);
    assert_eq!(subscriber_b.sync().await?, 0);

    println!("> Author gives Subscriber A write permission");
    let new_keyload_as_author = author
        .send_keyload(
            BRANCH1,
            author
                .subscribers()
                .map(|s| {
                    if s == &subscriber_a_id {
                        Permissioned::ReadWrite(s.clone(), PermissionDuration::Perpetual)
                    } else {
                        Permissioned::Read(s.clone())
                    }
                })
                .collect::<Vec<_>>()
                .iter()
                .map(Permissioned::as_ref),
            [psk.to_pskid()],
        )
        .await?;
    print_send_result(&new_keyload_as_author);
    println!("> Subscriber A publishes signed packet");
    assert_eq!(subscriber_a.sync().await?, 1);
    let signed_packet_as_a = subscriber_a
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    print_send_result(&signed_packet_as_a);
    print_user("Subscriber A", &subscriber_a);

    println!("> The other users receive the signed packet sent by Subscriber A");
    assert_eq!(author.sync().await?, 1);
    print_user("Author", &author);
    assert_eq!(subscriber_b.sync().await?, 2);
    print_user("Subscriber B", &subscriber_b);
    assert_eq!(subscriber_c.sync().await?, 2);
    print_user("Subscriber C", &subscriber_c);

    println!("> Backup & restore users");
    let author_backup = author.backup("my secret backup password").await?;
    println!("  Author backup size: {} Bytes", author_backup.len());
    let new_author = User::restore(&author_backup, "my secret backup password", transport.clone()).await?;
    print_user("Recovered Author", &new_author);
    assert_eq!(author, new_author);
    author = new_author;

    let subscriber_a_backup = subscriber_a.backup("my secret backup password").await?;
    println!("  Subscriber A backup size: {} Bytes", subscriber_a_backup.len());
    let new_subscriber_a = User::restore(&subscriber_a_backup, "my secret backup password", transport.clone()).await?;
    print_user("Recovered Subscriber A", &new_subscriber_a);
    assert_eq!(subscriber_a, new_subscriber_a);
    subscriber_a = new_subscriber_a;

    let subscriber_b_backup = subscriber_b.backup("my secret backup password").await?;
    println!("  Subscriber B backup size: {} Bytes", subscriber_b_backup.len());
    let new_subscriber_b = User::restore(&subscriber_b_backup, "my secret backup password", transport.clone()).await?;
    print_user("Recovered Subscriber B", &new_subscriber_b);
    assert_eq!(subscriber_b, new_subscriber_b);
    subscriber_b = new_subscriber_b;

    let subscriber_c_backup = subscriber_c.backup("my secret backup password").await?;
    println!("  Subscriber C backup size: {} Bytes", subscriber_c_backup.len());
    let new_subscriber_c = User::restore(&subscriber_c_backup, "my secret backup password", transport.clone()).await?;
    print_user("Recovered Subscriber C", &new_subscriber_c);
    assert_eq!(subscriber_c, new_subscriber_c);
    subscriber_c = new_subscriber_c;

    let failed_recovery: Result<User<_>> =
        User::restore(&subscriber_c_backup, "wrong password", transport.clone()).await;
    assert!(failed_recovery.is_err());

    println!("> Statelessly recover users rereading the stream");
    let mut new_author = User::builder()
        .with_identity(Ed25519::from_seed(author_seed))
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();
    // OOB data must be recovered manually
    new_author.add_subscriber(subscriber_b_id.clone());
    new_author.receive_message(announcement.address()).await?;
    new_author.receive_message(subscription_a_as_a.address()).await?;
    assert_eq!(new_author.sync().await?, 7);
    print_user("Recovered Author", &new_author);
    assert_eq!(author, new_author);
    author = new_author;

    let mut new_subscriber_a = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERA9SEED"))
        .with_transport(transport.clone())
        .build();

    new_subscriber_a.receive_message(announcement.address()).await?;
    assert_eq!(new_subscriber_a.sync().await?, 7);
    print_user("Recovered Subscriber A", &new_subscriber_a);
    assert_eq!(subscriber_a, new_subscriber_a);
    subscriber_a = new_subscriber_a;

    let mut new_subscriber_b = User::builder()
        .with_identity(Ed25519::from_seed("SUBSCRIBERB9SEED"))
        .with_transport(transport.clone())
        .build();
    new_subscriber_b.receive_message(announcement.address()).await?;
    assert_eq!(new_subscriber_b.sync().await?, 6);
    print_user("Recovered Subscriber B", &new_subscriber_b);
    assert_eq!(subscriber_b, new_subscriber_b);
    subscriber_b = new_subscriber_b;

    let mut new_subscriber_c = User::builder()
        .with_psk(psk.to_pskid(), psk)
        .with_transport(transport.clone())
        .build();
    new_subscriber_c.receive_message(announcement.address()).await?;
    assert_eq!(new_subscriber_c.sync().await?, 7);
    print_user("Recovered Subscriber C", &new_subscriber_c);
    assert_eq!(subscriber_c, new_subscriber_c);
    subscriber_c = new_subscriber_c;

    println!("> Author manually unsubscribes Subscriber A");
    author.remove_subscriber(
        subscription_a_as_author
            .as_subscription()
            .expect("message is supposed to be a subscription")
            .subscriber_identifier(),
    );
    print_user("Author", &author);

    println!("> The rest of subscribers also manually unsubscribe Subscriber A");
    // Manual unsubscription assumes an exchange of identifiers at application level
    subscriber_b.remove_subscriber(&subscriber_a_id);
    print_user("Subscriber B", &subscriber_b);
    subscriber_c.remove_subscriber(&subscriber_a_id);
    print_user("Subscriber C", &subscriber_c);

    println!("> ~Subscriber B sends unsubscription~ [CURRENTLY BROKEN]");
    // let unsubscription = subscriber_b.unsubscribe(new_keyload_as_b.address().relative()).await?;
    // print_send_result(&unsubscription);
    // print_user("Subscriber B", &subscriber_b);
    // println!("> Author receives unsubscription");
    // assert_eq!(author.sync().await?, 1);
    // print_user("Author", &author);

    println!("> ~The rest of subscribers also receive the unsubscription~ [CURRENTLY BROKEN]");
    // assert_eq!(subscriber_a.sync().await?, 1);
    // print_user("Subscriber A", &subscriber_a);
    // assert_eq!(subscriber_c.sync().await?, 1);
    // print_user("Subscriber C", &subscriber_c);
    println!("> Alternative: users manually unsubscribe Subscriber B");
    author.remove_subscriber(&subscriber_b_id);
    print_user("Author", &author);
    subscriber_a.remove_subscriber(&subscriber_b_id);
    print_user("Subscriber A", &subscriber_a);
    subscriber_c.remove_subscriber(&subscriber_b_id);
    print_user("Subscriber C", &subscriber_c);

    println!("> Author removes PSK");
    author.remove_psk(psk.to_pskid());
    print_user("Author", &author);

    println!("> Author issues a new keyload to remove all subscribers from the branch");
    let last_keyload = author.send_keyload_for_all(BRANCH1).await?;
    print_send_result(&last_keyload);
    print_user("Author", &author);
    println!("> Author sends a new signed packet");
    let last_signed_packet = author
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await?;
    print_send_result(&last_signed_packet);
    print_user("Author", &author);

    println!("> Subscriber A can only read the last keyload");
    let next_messages = subscriber_a.fetch_next_messages().await?;
    print_user("Subscriber A", &subscriber_a);
    assert!(
        !next_messages
            .iter()
            .any(|msg| msg.address() == last_signed_packet.address()),
        "Subscriber A did not expect the latest signed message"
    );

    println!("> Subscriber B can only read the last keyload");
    let next_messages = subscriber_b.fetch_next_messages().await?;
    print_user("Subscriber B", &subscriber_b);
    assert!(
        !next_messages
            .iter()
            .any(|msg| msg.address() == last_signed_packet.address()),
        "Subscriber B did not expect the latest signed message"
    );

    println!("> Subscriber C can only read the last keyload");
    let next_messages = subscriber_c.fetch_next_messages().await?;
    print_user("Subscriber C", &subscriber_c);
    assert!(
        !next_messages
            .iter()
            .any(|msg| msg.address() == last_signed_packet.address()),
        "Subscriber C did not expect the latest signed message"
    );

    println!("> Subscribers A and B try to send a signed packet");
    // TODO: THIS SHOULD FAIL ONCE PUBLISHERS ARE TRACKED BY BRANCH AND WE CAN "DEMOTE" SUBSCRIBERS
    let result = subscriber_a
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;
    print_user("Subscriber A", &subscriber_a);
    assert!(result.is_err());
    let result = subscriber_b
        .send_signed_packet(BRANCH1, PUBLIC_PAYLOAD, MASKED_PAYLOAD)
        .await;
    print_user("Subscriber B", &subscriber_b);
    assert!(result.is_err());

    println!("> The messages are not received by the rest of the subscribers");
    assert_eq!(author.sync().await?, 0);
    print_user("Author", &author);
    assert_eq!(subscriber_a.sync().await?, 0);
    print_user("Subscriber A", &subscriber_a);
    assert_eq!(subscriber_b.sync().await?, 0);
    print_user("Subscriber B", &subscriber_b);
    assert_eq!(subscriber_c.sync().await?, 0);
    print_user("Subscriber C", &subscriber_c);

    println!("> Author adds Subscriber A again and grants them Admin privileges");
    print_user("Author", &author);
    assert!(author.add_subscriber(subscriber_a_id.clone()));
    let subscriber_a_admin_permission = Permissioned::Admin(&subscriber_a_id);
    author
        .send_keyload(BRANCH1, vec![subscriber_a_admin_permission], vec![])
        .await?;
    print_user("Author", &author);

    println!("> Subscriber A receives keyload");
    let next_messages = subscriber_a.fetch_next_messages().await?;
    print_user("Subscriber A", &subscriber_a);
    let last_msg_as_a = next_messages
        .last()
        .expect("Subscriber A has not received the latest keyload");
    assert!(
        last_msg_as_a.is_keyload(),
        "Subscriber A expected the last message to be a keyload message, found {:?} instead",
        last_msg_as_a.content()
    );
    assert!(
        last_msg_as_a
            .as_keyload()
            .unwrap()
            .subscribers
            .contains(&subscriber_a_admin_permission.into()),
        "Subscriber A expected that they would be included with admin privileges in keyload"
    );

    println!("> Author creates a new branch");
    author.new_branch(BRANCH1, BRANCH2).await?;
    print_user("Author", &author);
    println!("> Subscriber A receives branch announcement");
    let next_messages = subscriber_a.fetch_next_messages().await?;
    print_user("Subscriber A", &subscriber_a);
    let last_msg_as_a = next_messages
        .last()
        .expect("Subscriber A has not received the latest branch announcement");
    assert!(
        last_msg_as_a.is_branch_announcement(),
        "Subscriber A expected the last message to be a branch announcement message, found {:?} instead",
        last_msg_as_a.content()
    );
    println!("> Subscriber A confirming they still have Admin privileges in new branch");
    assert!(
        subscriber_a
            .permission(&BRANCH2.into())
            .expect("Subscriber A should have a permission stored for new branch")
            .is_admin(),
        "Subscriber A expected to still have Admin privileges in new branch"
    );

    Ok(())
}
