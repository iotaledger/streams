use std::{cell::RefCell, collections::HashMap, rc::Rc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::Rng;

use streams::{id::Ed25519, transport::Transport, Address, TransportMessage, User};

const LIFESPAN: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<()> {
    let transient_transport = Rc::new(RefCell::new(TransientStorage::new()));
    tokio::time::sleep(LIFESPAN).await;
    // Subscriber receives announcement even if LIFESPAN HAS EXPIRED
    subscriber.receive_message(announcement.address()).await?;
    Ok(())
}

async fn author(transport: Rc<RefCell<TransientStorage>>) -> Result<()> {
    let mut author = User::builder()
        .with_identity(Ed25519::from_seed("transient-messages example author seed"))
        .with_transport(transport.clone())
        .build()?;
    loop {
        let announcement = author.create_stream(rand::thread_rng().gen()).await?;
    }
}

async fn subscriber(transport: Rc<RefCell<TransientStorage>>) -> Result<()> {
    let mut subscriber = User::builder()
        .with_identity(Ed25519::from_seed("transient-messages example subscriber seed"))
        .with_transport(transport)
        .build()?;
    loop {
        let announcement = author.create_stream(rand::thread_rng().gen()).await?;
    }
}

struct TransientStorage(HashMap<Address, (TransportMessage, DateTime<Utc>)>);

impl TransientStorage {
    fn new() -> Self {
        Self(HashMap::new())
    }
}

#[async_trait(?Send)]
impl Transport<'_> for TransientStorage {
    type Msg = TransportMessage;
    type SendResponse = (TransportMessage, DateTime<Utc>);

    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse> {
        let timed_msg = (msg, Utc::now() + chrono::Duration::from_std(LIFESPAN).unwrap());
        self.0.insert(address, timed_msg.clone());
        Ok(timed_msg)
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>> {
        let (msg, ts) = self
            .0
            .remove(&address)
            .filter(|(_, ts)| ts > &Utc::now())
            .ok_or_else(|| anyhow!("message not found"))?;
        self.0.insert(address, (msg.clone(), ts));
        Ok(vec![msg])
    }
}

// TODO: USE TANGLE MESSAGES AS INDEXING MESSAGES, ATTEMPTING TO BE ABLE TO PREDICT MSG-ID?
// IDEA: REPORT NEXT MSG NONCE IN PREVIOUS MSG
