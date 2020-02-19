use failure::{bail, Fallible};
use std::collections::HashMap;
use std::hash;

use crate::message::TrinaryMessage;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
pub trait Transport<Link> /*where Link: HasLink*/ {
    /// Send a message.
    fn send_message(&mut self, msg: &TrinaryMessage<Link>) -> Fallible<()>;

    /// Receive a message;
    fn recv_message(&mut self, link: &Link) -> Fallible<Vec<TrinaryMessage<Link>>>;
}

pub mod tangle;

pub struct BucketTransport<Link> {
    bucket: HashMap<Link, Vec<TrinaryMessage<Link>>>,
}

impl<Link> Transport<Link> for BucketTransport<Link>
where
    Link: Eq + hash::Hash + Clone,
{
    fn send_message(&mut self, msg: &TrinaryMessage<Link>) -> Fallible<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    fn recv_message(&mut self, link: &Link) -> Fallible<Vec<TrinaryMessage<Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}
