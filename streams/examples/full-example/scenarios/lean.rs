// Rust

// 3rd-party
use lets::id::Identity;

// IOTA

// Streams
use streams::{
    id::{Ed25519, Psk},
    Result, SendResponse, User,
};

// Local
use crate::GenericTransport;

const PAYLOAD: &[u8] = b"MASKEDPAYLOAD";

const BASE_BRANCH: &str = "BASE_BRANCH";
const BRANCH1: &str = "BRANCH1";
const BRANCH2: &str = "BRANCH2";

pub(crate) async fn example<SR, T: GenericTransport<SR>>(transport: T, author_seed: &str) -> Result<()> {
    let psk = Psk::from_seed("unique psk seed");

    let mut author = User::builder()
        .with_transport(transport.clone())
        .with_identity(Identity::from(Ed25519::from_seed(author_seed)))
        .with_psk(psk.to_pskid(), psk)
        .lean()
        .build();
    let mut fat_subscriber = User::builder()
        .with_transport(transport.clone())
        .with_psk(psk.to_pskid(), psk)
        .build();
    let mut lean_subscriber = User::builder()
        .with_transport(transport)
        .with_psk(psk.to_pskid(), psk)
        .lean()
        .build();

    println!("author creates channel");
    let announcement = author.create_stream(BASE_BRANCH).await?;

    fat_subscriber.receive_message(announcement.address()).await?;
    lean_subscriber.receive_message(announcement.address()).await?;

    println!("author sends a few messages to the base branch");
    let first_message = author.message().with_payload(PAYLOAD).signed().send().await?;
    let _second_message = author.message().with_payload(PAYLOAD).signed().send().await?;
    let middle_message = author.message().with_payload(PAYLOAD).signed().send().await?;
    let _third_message = author.message().with_payload(PAYLOAD).signed().send().await?;
    let last_message = author.message().with_payload(PAYLOAD).signed().send().await?;

    // sync subscribers to retrieve all available messages
    sync_subs(&mut fat_subscriber, &mut lean_subscriber).await?;
    // each subscriber tries to retrieve specific messages from the branch
    retrieve_messages(
        &mut fat_subscriber,
        &mut lean_subscriber,
        first_message,
        middle_message,
        last_message,
    )
    .await?;

    println!("author creates 2 new branch and sends messages to each one");
    author.new_branch(BASE_BRANCH, BRANCH1).await?;
    for _ in 0..20 {
        author
            .message()
            .with_topic(BRANCH1)
            .with_payload(PAYLOAD)
            .signed()
            .send()
            .await?;
    }

    author.new_branch(BASE_BRANCH, BRANCH2).await?;
    for _ in 0..20 {
        author
            .message()
            .with_topic(BRANCH2)
            .with_payload(PAYLOAD)
            .signed()
            .send()
            .await?;
    }

    // sync the subscribers again and compare user size
    sync_subs(&mut fat_subscriber, &mut lean_subscriber).await?;

    Ok(())
}

async fn sync_subs<SR, T: GenericTransport<SR>>(fat: &mut User<T>, lean: &mut User<T>) -> Result<()> {
    print!("\nsubscribers syncing...");
    fat.sync().await?;
    lean.sync().await?;
    println!("done");

    let fat_backup = fat.backup("password").await?;
    let lean_backup = lean.backup("password").await?;

    assert!(fat_backup.len() > lean_backup.len());
    println!("\tlean backup size: {} Bytes", lean_backup.len());
    println!("\tfat backup size: {} Bytes\n", fat_backup.len());
    Ok(())
}

async fn retrieve_messages<SR, T: GenericTransport<SR>, TSR>(
    fat_subscriber: &mut User<T>,
    lean_subscriber: &mut User<T>,
    first_message: SendResponse<TSR>,
    middle_message: SendResponse<TSR>,
    last_message: SendResponse<TSR>,
) -> Result<()> {
    println!("\nfat subscriber tries to retrieve first, middle and last messages...");
    // The fat subscriber will be able to retrieve any previously received message again, as all
    // spongos states remainn stored in the user implementation
    let received_first_message_as_fat = fat_subscriber.receive_message(first_message.address()).await;
    assert!(
        received_first_message_as_fat.is_ok(),
        "fat subscriber should be able to read the first message in base branch"
    );
    let received_second_message_as_fat = fat_subscriber.receive_message(middle_message.address()).await;
    assert!(
        received_second_message_as_fat.is_ok(),
        "fat subscriber should be able to read the middle message in base branch"
    );
    let received_last_message_as_fat = fat_subscriber.receive_message(last_message.address()).await;
    assert!(
        received_last_message_as_fat.is_ok(),
        "fat subscriber should be able to read the third message in base branch"
    );
    println!("fat subscriber was able to retrieve all three messages");

    println!("\nlean subscriber tries to retrieve first, middle and last messages...");
    // The lean subscriber will be able to receive the first message because it is linked to the
    // announcement message, who's spongos state will always be stored
    let received_first_message_as_lean = lean_subscriber.receive_message(first_message.address()).await;
    assert!(
        received_first_message_as_lean.is_ok(),
        "lean subscriber should be able to read the first message"
    );
    // The lean subscriber will not be able to receive the middle message because it is linked to a
    // pruned spongos state (first_message)
    let received_second_message_as_lean = lean_subscriber.receive_message(middle_message.address()).await?;
    assert!(
        received_second_message_as_lean.is_orphan(),
        "lean subscriber should not be able to read the middle message"
    );
    // The lean subscriber will also be able to receive the last message, because it is the latest
    // spongos state to have been stored
    let received_last_message_as_lean = lean_subscriber.receive_message(last_message.address()).await;
    assert!(
        received_last_message_as_lean.is_ok(),
        "lean subscriber should be able to read the last message"
    );
    println!("lean subscriber was able to read first and last message, but not the middle, as expected\n");

    Ok(())
}
