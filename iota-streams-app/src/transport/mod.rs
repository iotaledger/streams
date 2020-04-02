use failure::{bail, Fallible};
use std::collections::HashMap;
use std::hash;

use crate::message::TbinaryMessage;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
pub trait Transport<TW, F, Link> /*where Link: HasLink*/ {
    /// Send a message.
    fn send_message(&mut self, msg: &TbinaryMessage<TW, F, Link>) -> Fallible<()>;

    /// Receive a message;
    fn recv_message(&mut self, link: &Link) -> Fallible<Vec<TbinaryMessage<TW, F, Link>>>;
}

pub struct BucketTransport<TW, F, Link> {
    bucket: HashMap<Link, Vec<TbinaryMessage<TW, F, Link>>>,
}

impl<TW, F, Link> Transport<TW, F, Link> for BucketTransport<TW, F, Link>
where
    TW: Clone,
    Link: Eq + hash::Hash + Clone,
{
    fn send_message(&mut self, msg: &TbinaryMessage<TW, F, Link>) -> Fallible<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    fn recv_message(&mut self, link: &Link) -> Fallible<Vec<TbinaryMessage<TW, F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}

pub mod tangle;
