// Rust

// 3rd-party

// IOTA

// Streams

// Local
use crate::GenericTransport;

pub async fn fetch_next_messages<T, S>(streamable: &mut S) -> Result<()>
where
    T: Transport,
    S: IntoMessages<T>,
{
    let mut msgs = streamable.messages();
    while let Some(msg) = msgs.try_next().await? {
        println!("Message exists at {}... ", &msg.link.rel());
    }
    println!("No more messages in sequence.");
    Ok(())
}
