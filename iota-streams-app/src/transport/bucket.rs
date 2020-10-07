use super::*;
use crate::message::LinkedMessage;

use iota_streams_core::prelude::HashMap;

pub struct BucketTransport<Link, Msg> {
    bucket: HashMap<Link, Vec<Msg>>,
}

impl<Link, Msg> Default for BucketTransport<Link, Msg> where
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self {
            bucket: HashMap::new(),
        }
    }
}

impl<Link, Msg> BucketTransport<Link, Msg> where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

impl<Link, Msg> TransportOptions for BucketTransport<Link, Msg> {
    type SendOptions = ();
    fn get_send_options(&self) -> () {}
    fn set_send_options(&mut self, _opt: ()) {}

    type RecvOptions = ();
    fn get_recv_options(&self) -> () {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone + core::fmt::Debug,
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
            Err(anyhow!("Link not found in the bucket: {:?}.", link))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg> where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync,
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
            Err(anyhow!("Link not found in the bucket."))
        }
    }

    async fn recv_message(&mut self, link: &Link) -> Result<Msg>
    {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }
}
