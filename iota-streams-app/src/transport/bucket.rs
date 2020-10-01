use super::*;

use iota_streams_core::prelude::HashMap;

pub struct BucketTransport<F, Link> {
    bucket: HashMap<Link, Vec<BinaryMessage<F, Link>>>,
}

impl<F, Link> BucketTransport<F, Link>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

#[cfg(not(feature = "async"))]
impl<F, Link> Transport<F, Link> for BucketTransport<F, Link>
where
    Link: Eq + hash::Hash + Clone,
{
    type SendOptions = ();

    fn send_message_with_options(&mut self, msg: &BinaryMessage<F, Link>, _opt: &()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    fn recv_messages_with_options(&mut self, link: &Link, _opt: &()) -> Result<Vec<BinaryMessage<F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            Err(anyhow!("Link not found in the bucket."))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<F, Link> Transport<F, Link> for BucketTransport<F, Link> where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync,
    F: 'static + core::marker::Send + core::marker::Sync,
{
    type SendOptions = ();

    async fn send_message_with_options(&mut self, msg: &BinaryMessage<F, Link>, _opt: &()) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    type RecvOptions = ();

    async fn recv_messages_with_options(&mut self, link: &Link, _opt: &()) -> Result<Vec<BinaryMessage<F, Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            Err(anyhow!("Link not found in the bucket."))
        }
    }
}
