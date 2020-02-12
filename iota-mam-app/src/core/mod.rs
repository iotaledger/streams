use iota_mam_core::trits::{Trits};

/// Type of "absolute" links. For http it's the absolute URL.
pub trait HasLink: Sized {
    /// Type of "base" links. For http it's domain name.
    type Base;
    fn base(&self) -> &Self::Base;

    /// Type of "relative" links. For http it's URL path.
    type Rel;
    fn rel(&self) -> &Self::Rel;

    fn from_base_rel(base: &Self::Base, rel: &Self::Rel) -> Self;
}

/// Abstraction-helper to generate message links.
pub trait LinkGenerator<Link, From> {
    fn link_from(&mut self, arg: &From) -> Link;
    //fn from_mss_public_key(&mut self, mss_pk: &mss::PublicKey) -> Link;
    //fn next_link(&mut self, link: &Link) -> Link;
}

/// Trinary network Message representation.
#[derive(Clone, Debug)]
pub struct TrinaryMessage<AbsLink> {
    /// Link -- message address.
    pub link: AbsLink,

    /// Message body -- header + content.
    pub body: Trits,
}
//TODO: Add PreparedMessage<Content>{ store, header, content, }
//TODO: Add PreprocessedMessage

impl<AbsLink> TrinaryMessage<AbsLink> {
    pub fn link(&self) -> &AbsLink {
        &self.link
    }
}

use crate::Result;
//use super::*;

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
pub trait Transport<Link> /*where Link: HasLink*/ {
    /// Send a message.
    fn send(&mut self, msg: TrinaryMessage<Link>) -> Result<()>;

    /// Receive a message;
    fn recv(&mut self, link: &Link) -> Result<Vec<TrinaryMessage<Link>>>;
}

pub mod msg;
pub mod transport;


use std::collections::HashMap;
use std::hash;
use failure::bail;

pub struct BucketTransport<Link> {
    bucket: HashMap<Link, Vec<TrinaryMessage<Link>>>,
}

impl<Link> Transport<Link> for BucketTransport<Link> where
    Link: Eq + hash::Hash + Clone
{
    fn send(&mut self, msg: TrinaryMessage<Link>) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg);
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg]);
            Ok(())
        }
    }

    fn recv(&mut self, link: &Link) -> Result<Vec<TrinaryMessage<Link>>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            bail!("Link not found in the bucket.")
        }
    }
}
