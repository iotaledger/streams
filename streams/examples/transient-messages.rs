use std::{collections::HashMap, fmt::Display, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use rand::Rng;
use streams::{id::Ed25519, transport::Transport, Address, TransportMessage, User};
use tokio::sync::{
    mpsc::{channel, Receiver},
    Mutex,
};

const LIFESPAN: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    let transport = TransientStorage::new();
    let mut author = User::builder()
        .with_identity(Ed25519::from_seed("transient-messages example author seed"))
        .with_transport(transport.clone())
        .build()?;
    let announcement = author.create_stream(4, LIFESPAN.as_secs() as u32).await?;
    print_author(format!("Announcement {}", announcement.address().msg()));

    let (subscription_sender, subscription_receiver) = channel(1);
    tokio::spawn(author_thread(author, announcement.address(), subscription_receiver));

    tokio::time::sleep(LIFESPAN).await;
    for n in 0.. {
        // Subscription handshake
        let mut subscriber = User::builder()
            .with_identity(Ed25519::from_seed(rand::thread_rng().gen::<[u8; 32]>()))
            .with_transport(transport.clone())
            .build()?;
        print_subscriber(n, format!("? Announcement {}", announcement.address().msg()));
        subscriber.receive_message(announcement.address()).await?;
        print_subscriber(n, format!("! Announcement: {}", announcement.address().msg()));
        let subscription = subscriber.subscribe(announcement.address().msg()).await?;
        print_subscriber(n, format!("Subscription {}", subscription.address().msg()));
        subscription_sender.send(subscription.address()).await?;
        tokio::time::sleep(Duration::from_secs(2)).await; // Wait for author to send some packets FFS :)
        let msgs = subscriber.fetch_next_messages().await?;
        assert_ne!(0, msgs.len(), "Subscriber {} has not received any packet", n);
        for msg in msgs {
            print_subscriber(n, format!("Packet {}", msg.address().msg()));
        }
        tokio::time::sleep(LIFESPAN).await;
    }

    Ok(())
}

async fn author_thread(
    mut author: User<TransientStorage>,
    mut last_msg: Address,
    mut subscriptions: Receiver<Address>,
) {
    let mut keyloads = 0;
    let start = Utc::now().timestamp();
    loop {
        if let Ok(subscription) = subscriptions.try_recv() {
            print_author(format!("? Subscription {}", subscription.msg()));
            author
                .receive_message(subscription)
                .await
                .expect("author should be able to fetch the new subscription from the transport layer");
            print_author(format!("! Subscription {}", subscription.msg()));
            let keyload = author
                .send_keyload_for_all_rw(last_msg.msg())
                .await
                .expect("author should be able to send a new Keyload");
            keyloads += 1;
            print_author(format!("Keyload {}", keyload.address().msg()));
            last_msg = keyload.address();
        }
        if keyloads < (Utc::now().timestamp() - start) / LIFESPAN.as_secs() as i64 {
            let keyload = author
                .send_keyload_for_all_rw(last_msg.msg())
                .await
                .expect("author should be able to send a new Keyload");
            keyloads += 1;
            print_author(format!("Keyload {}", keyload.address().msg()));
            last_msg = keyload.address();
        }
        let announcement = author
            .send_announcement()
            .await
            .expect("author should be able to resend the announcement of the Stream");
        print_author(format!("Announcement {}", announcement.address().msg()));
        let packet = author
            .send_signed_packet(last_msg.msg(), "public", "masked")
            .await
            .expect("author should be able to send a new packet");
        print_author(format!("Packet {}", packet.address().msg()));
        last_msg = packet.address();
        tokio::time::sleep(Duration::from_secs(1)).await;
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

fn print_subscriber<T>(n: usize, log: T)
where
    T: Display,
{
    println!("\t\t\t\t\t[Subscriber {}] {}", n, log);
}

// PROBLEM: collision between keyloads sent manually and keyloads sent automatically.
