use super::*;
use crate::message::LinkedMessage;
use core::hash;

use iota_streams_core::{
    err,
    prelude::{
        string::ToString,
        HashMap,
    },
    Errors::MessageLinkNotFound,
    LOCATION_LOG,
};

#[cfg(feature = "async")]
use iota_streams_core::Errors::MessageNotUnique;

pub struct BucketTransport<Link, Msg> {
    bucket: HashMap<Link, Vec<Msg>>,
}

impl<Link, Msg> Default for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self { bucket: HashMap::new() }
    }
}

impl<Link, Msg> BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

impl<Link, Msg> TransportOptions for BucketTransport<Link, Msg> {
    type SendOptions = ();
    fn get_send_options(&self) {}
    fn set_send_options(&mut self, _opt: ()) {}

    type RecvOptions = ();
    fn get_recv_options(&self) {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone + core::fmt::Debug + core::fmt::Display,
    Msg: LinkedMessage<Link> + Clone,
{
    fn send_message(&mut self, msg: &Msg) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync + core::fmt::Display,
    Msg: LinkedMessage<Link> + Clone + core::marker::Send + core::marker::Sync,
{
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }

    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string())).unwrap();
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))?
        }
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<Link, Msg> Transport<Link, Msg> for Arc<AtomicRefCell<BucketTransport<Link, Msg>>> where
    // Link: 'static + core::marker::Send + core::marker::Sync,
    // Msg: 'static + core::marker::Send + core::marker::Sync,
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync + core::fmt::Display,
    Msg: LinkedMessage<Link> + Clone + core::marker::Send + core::marker::Sync + core::fmt::Debug,
{
    /// Send a message.
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        // assert!(false);
        let bucket = &mut (&*self).borrow_mut().bucket;
        if let Some(msgs) = bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        let bucket = &(&*self).borrow().bucket;
        if let Some(msgs) = bucket.get(link) {
            Ok(msgs.clone())
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        let bucket = &(&*self).borrow().bucket;
        if let Some(msgs) = bucket.get(link) {
            try_or!(!msgs.is_empty(), MessageLinkNotFound(link.to_string()))?;
            try_or!(1 == msgs.len(), MessageNotUnique(link.to_string()))?;
            Ok(msgs[0].clone())
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}
