use std::{collections::HashMap, fmt::Display, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use rand::Rng;
use streams::{
    id::Ed25519,
    transport::{tangle, Transport},
    Address, TransportMessage, User,
};
use tokio::sync::{mpsc, watch, Mutex};

const LIFESPAN: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let transport = tangle::Client::for_node("http://65.108.208.75:14265").await?;
    let mut author = User::builder()
        .with_identity(Ed25519::from_seed("transient-messages example author seed"))
        .with_transport(transport)
        .build()?;
    let announcement = author
        .create_stream(rand::thread_rng().gen(), LIFESPAN.as_secs() as u32)
        .await?;
    print_author(format!("[Sent][Announcement]     {} ", announcement.address().msg()));

    let transport = tangle::Client::for_node("http://65.108.208.75:14265").await?;
    let mut long_subscriber = User::builder()
        .with_identity(Ed25519::from_seed(
            "transient-messages example long-running subscriber seed",
        ))
        .with_transport(transport)
        .build()?;
    long_subscriber.receive_message(announcement.address()).await?;
    print_long_subscriber(format!("[Received][Announcement] {} ", announcement.address().msg()));

    let subscription = long_subscriber.subscribe(announcement.address().msg()).await?;
    print_long_subscriber(format!("[Sent][Subscription]     {} ", subscription.address().msg()));

    author.receive_message(subscription.address()).await?;
    print_author(format!("[Received][Subscription] {} ", subscription.address().msg()));
    let keyload = author.send_keyload_for_all_rw(announcement.address().msg()).await?;
    print_author(format!("[Sent][Keyload]          {} ", keyload.address().msg()));

    long_subscriber.sync().await?;
    let packet = long_subscriber
        .send_signed_packet(keyload.address().msg(), "public", "masked")
        .await?;
    print_long_subscriber(format!("[Sent][Packet]           {} ", packet.address().msg()));
    let (subscription_sender, subscription_receiver) = mpsc::channel(1);
    let (snapshot_sender, mut snapshot_receiver) = watch::channel(());
    tokio::spawn(author_thread(
        author,
        announcement.address(),
        subscription_receiver,
        snapshot_sender,
    ));
    let (long_subscriber_last_msg_sender, mut long_subscriber_last_msg_receiver) = watch::channel(packet.address());
    tokio::spawn(long_running_subscriber_thread(
        long_subscriber,
        long_subscriber_last_msg_sender,
    ));

    tokio::time::sleep(LIFESPAN).await;
    for n in 1.. {
        // Subscription handshake
        let transport: tangle::Client = tangle::Client::for_node("http://65.108.208.75:14265").await?;
        let mut subscriber = User::builder()
            .with_identity(Ed25519::from_seed(rand::thread_rng().gen::<[u8; 32]>()))
            .with_transport(transport)
            .build()?;
        subscriber.receive_message(announcement.address()).await?;
        print_subscriber(n, format!("[Received][Announcement] {} ", announcement.address().msg()));
        snapshot_receiver
            .changed()
            .await
            .expect("snapshot channel should remain permanently open");
        let subscription = subscriber.subscribe(announcement.address().msg()).await?;
        print_subscriber(n, format!("[Sent][Subscription]     {} ", subscription.address().msg()));
        subscription_sender.send(subscription.address()).await?;
        snapshot_receiver.changed().await?;
        long_subscriber_last_msg_receiver.changed().await?;
        let long_subscriber_last_msg = *long_subscriber_last_msg_receiver.borrow();
        let mut msgs = subscriber.fetch_next_messages().await?;
        let mut includes_long_subscriber_last_msg = msgs.iter().any(|msg| msg.address() == long_subscriber_last_msg);
        if msgs.is_empty() || !includes_long_subscriber_last_msg {
            // Snapshots race against other packets. The subscriber eventually syncs
            snapshot_receiver.changed().await?;
            // Wait twice for a new value, to ensure it was sent after the snapshot
            long_subscriber_last_msg_receiver.changed().await?;
            long_subscriber_last_msg_receiver.changed().await?;
            let long_subscriber_last_msg = *long_subscriber_last_msg_receiver.borrow();
            msgs.extend(subscriber.fetch_next_messages().await?);
            includes_long_subscriber_last_msg = msgs.iter().any(|msg| msg.address() == long_subscriber_last_msg);
        }
        assert_ne!(0, msgs.len(), "Subscriber {} has not received any packet", n);
        assert!(includes_long_subscriber_last_msg);
        for msg in msgs {
            if msg.is_signed_packet() {
                print_subscriber(n, format!("[Received][Packet]       {} ", msg.address().msg()));
            } else if msg.is_keyload() {
                print_subscriber(n, format!("[Received][Keyload]      {} ", msg.address().msg()));
            } else {
                panic!("Received {:?}", msg);
            }
        }
        subscriber.unsubscribe(announcement.address().msg()).await?;
        tokio::time::sleep(LIFESPAN).await;
    }

    Ok(())
}

async fn long_running_subscriber_thread(mut subscriber: User<tangle::Client>, last_msg: watch::Sender<Address>) {
    loop {
        let msgs = subscriber
            .fetch_next_messages()
            .await
            .expect("long running subscriber should be able to fetch messages");
        let last_msg_received = msgs
            .last()
            .map(|msg| msg.address())
            .unwrap_or_else(|| *last_msg.borrow());
        let packet = subscriber
            .send_signed_packet(last_msg_received.msg(), "public", "masked")
            .await
            .expect("long running subscriber should be able to send signed packets");
        last_msg
            .send(packet.address())
            .expect("last-msg channel should remain permanently open");
        print_long_subscriber(format!("[Sent][Packet]           {}", packet.address().msg(),));
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn author_thread(
    mut author: User<tangle::Client>,
    mut last_msg: Address,
    mut subscriptions: mpsc::Receiver<Address>,
    snapshot_signal: watch::Sender<()>,
) {
    let mut snapshots = 0;
    let start = Utc::now().timestamp();
    loop {
        if let Ok(subscription) = subscriptions.try_recv() {
            author
                .receive_message(subscription)
                .await
                .expect("author should be able to fetch the new subscription from the transport layer");
            print_author(format!("[Received][Subscription] {} ", subscription.msg()));
            let keyload = author
                .send_keyload_for_all_rw(last_msg.msg())
                .await
                .expect("author should be able to send a new Keyload");
            print_author(format!("[Sent][Keyload]          {} ", keyload.address().msg()));
            last_msg = keyload.address();
        }
        if snapshots <= (Utc::now().timestamp() - start) / (LIFESPAN.as_secs() as i64 / 2) {
            author.sync().await.expect("author should be able to sync the stream");
            let snapshot = author
                .send_snapshot(last_msg.msg())
                .await
                .expect("author should be able to send a new Keyload");
            snapshot_signal
                .send(())
                .expect("snapshots channel should always remain open");
            snapshots += 1;
            print_author(format!("[Sent][Snapshot]         {} ", snapshot.address().msg()));
            last_msg = snapshot.address();
        }
        let announcement = author
            .send_announcement()
            .await
            .expect("author should be able to resend the announcement of the Stream");
        print_author(format!("[Sent][Announcement]     {} ", announcement.address().msg()));
        let packet = author
            .send_signed_packet(last_msg.msg(), "public", "masked")
            .await
            .expect("author should be able to send a new packet");
        print_author(format!("[Sent][Packet]           {} ", packet.address().msg()));
        last_msg = packet.address();
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct TransientStorage(Arc<Mutex<HashMap<Address, (TransportMessage, DateTime<Utc>)>>>);

impl TransientStorage {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }
}

#[async_trait]
impl Transport<'_> for TransientStorage {
    type Msg = TransportMessage;
    type SendResponse = (TransportMessage, DateTime<Utc>);

    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse> {
        let timed_msg = (msg, Utc::now() + chrono::Duration::from_std(LIFESPAN).unwrap());
        self.0.lock().await.insert(address, timed_msg.clone());
        Ok(timed_msg)
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>> {
        let mut store = self.0.lock().await;
        let (msg, ts) = store
            .remove(&address)
            .filter(|(_, ts)| ts > &Utc::now())
            .ok_or_else(|| anyhow!("message not found"))?;
        store.insert(address, (msg.clone(), ts));
        Ok(vec![msg])
    }
}

fn print_author<T>(log: T)
where
    T: Display,
{
    println!("[Author] {}", log);
}

fn print_long_subscriber<T>(log: T)
where
    T: Display,
{
    println!("\t\t\t\t\t\t\t     [Subscriber 0] {}", log);
}

fn print_subscriber<T>(n: usize, log: T)
where
    T: Display,
{
    println!("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t [Subscriber {}] {}", n, log);
}

// TODO: SEPARATE KEYLOADS FROM SNAPSHOTS
