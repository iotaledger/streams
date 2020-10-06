use super::*;
use crate::message::LinkedMessage;

use iota_streams_core::prelude::HashMap;

pub struct BucketTransport<Link, Msg> {
    bucket: HashMap<Link, Vec<Msg>>,
}

impl<Link, Msg> BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

#[cfg(not(feature = "async"))]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone,
    Msg: LinkedMessage<Link> + Clone,
{
    type SendOptions = ();

    fn send_message_with_options(&mut self, msg: &Msg, _opt: &()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    fn recv_messages_with_options(&mut self, link: &Link, _opt: &()) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            Err(anyhow!("Link not found in the bucket."))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg> where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync,
    Msg: LinkedMessage<Link> + Clone + core::marker::Send + core::marker::Sync,
{
    type SendOptions = ();

    async fn send_message_with_options(&mut self, msg: &Msg, _opt: &()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    async fn recv_messages_with_options(&mut self, link: &Link, _opt: &()) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            Err(anyhow!("Link not found in the bucket."))
        }
    }
}
