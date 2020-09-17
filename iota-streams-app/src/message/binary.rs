use anyhow::Result;
use core::fmt;

use super::*;
use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_ddml::{
    command::unwrap,
    link_store::EmptyLinkStore,
    types::*,
};

/// Binary network Message representation.
pub struct BinaryMessage<F, AbsLink> {
    /// Link -- message address.
    pub link: AbsLink,

    /// Message body -- header + content.
    pub body: Vec<u8>,

    pub(crate) _phantom: core::marker::PhantomData<F>,
}

impl<F, AbsLink> PartialEq for BinaryMessage<F, AbsLink>
where
    AbsLink: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.link.eq(&other.link) && self.body.eq(&other.body)
    }
}

impl<F, AbsLink> fmt::Debug for BinaryMessage<F, AbsLink>
where
    AbsLink: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{link: {:?}, body: {:?}}}", self.link, self.body)
    }
}

impl<F, AbsLink> fmt::Display for BinaryMessage<F, AbsLink>
where
    AbsLink: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{link: {}, body: {:?}}}", self.link, self.body)
    }
}

impl<F, AbsLink> Clone for BinaryMessage<F, AbsLink>
where
    AbsLink: Clone,
{
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            body: self.body.clone(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, AbsLink> BinaryMessage<F, AbsLink> {
    pub fn new(link: AbsLink, body: Vec<u8>) -> Self {
        Self {
            link,
            body,
            _phantom: core::marker::PhantomData,
        }
    }
    pub fn link(&self) -> &AbsLink {
        &self.link
    }
}

impl<F, Link> BinaryMessage<F, Link>
where
    F: PRP,
    Link: Clone + AbsorbExternalFallback<F>,
{
    pub fn parse_header<'a>(&'a self) -> Result<PreparsedMessage<'a, F, Link>> {
        let mut ctx = unwrap::Context::new(&self.body[..]);
        let mut header = HDF::<Link>::new(self.link().clone());
        let store = EmptyLinkStore::<F, Link, ()>::default();
        header.unwrap(&store, &mut ctx)?;

        Ok(PreparsedMessage {
            header: header,
            ctx: ctx,
        })
    }
}
