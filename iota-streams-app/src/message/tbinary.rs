use failure::Fallible;
use std::fmt;

use super::*;
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            SpongosTbitWord,
            StringTbitWord,
        },
        Tbits,
    },
};
use iota_streams_protobuf3::{
    command::unwrap,
    types::*,
};

/// Trinary network Message representation.
pub struct TbinaryMessage<TW, F, AbsLink> {
    /// Link -- message address.
    pub link: AbsLink,

    /// Message body -- header + content.
    pub body: Tbits<TW>,

    pub(crate) _phantom: std::marker::PhantomData<F>,
}

impl<TW, F, AbsLink> fmt::Display for TbinaryMessage<TW, F, AbsLink>
where
    TW: StringTbitWord,
    AbsLink: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{link: {}, body: {}}}", self.link, self.body)
    }
}

impl<TW, F, AbsLink> Clone for TbinaryMessage<TW, F, AbsLink>
where
    TW: Clone,
    AbsLink: Clone,
{
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            body: self.body.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F, AbsLink> TbinaryMessage<TW, F, AbsLink> {
    pub fn new(link: AbsLink, body: Tbits<TW>) -> Self {
        Self {
            link,
            body,
            _phantom: std::marker::PhantomData,
        }
    }
    pub fn link(&self) -> &AbsLink {
        &self.link
    }
}

impl<TW, F, Link> TbinaryMessage<TW, F, Link>
where
    TW: SpongosTbitWord + StringTbitWord + trinary::TritWord,
    F: PRP<TW> + Default,
    Link: Clone + AbsorbExternalFallback<TW, F>,
{
    pub fn parse_header<'a>(&'a self) -> Fallible<PreparsedMessage<'a, TW, F, Link>> {
        let mut ctx = unwrap::Context::new(self.body.slice());
        let mut header = Header::<TW, Link>::new(self.link().clone());
        let store = EmptyLinkStore::<TW, F, Link, ()>::default();
        header.unwrap(&store, &mut ctx)?;

        Ok(PreparsedMessage {
            header: header,
            ctx: ctx,
        })
    }
}
