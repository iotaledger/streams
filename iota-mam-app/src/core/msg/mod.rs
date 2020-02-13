use failure::ensure;
use std::cell::{Ref, RefMut};
use std::string::ToString;

use iota_mam_core::{trits::{Trits, TritSlice}, spongos::Spongos};
use iota_mam_protobuf3::{io, types::*, command::{sizeof, wrap, unwrap}};

use crate::Result;
use super::*;

use header::Header;

pub(crate) trait ContentWrap<Store> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context>;
    fn wrap<'c, OS: io::OStream>(&self, store: &Store, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>>;
}

/// Result of wrapping the message.
pub struct WrappedMessage<Link> {
    pub message: TrinaryMessage<Link>,
    spongos: Spongos,
}

impl<Link> WrappedMessage<Link> where
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(mut self, mut store: RefMut<Store>, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> where
    Store: LinkStore<<Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.message.link.rel(), self.spongos, info)?;
        Ok(self.message)
    }
}

/// Message context prepared for wrapping.
pub struct PreparedMessage<'a, Link, Store: 'a, Content> {
    store: Ref<'a, Store>,
    pub header: Header<Link>,
    pub content: Content,
}

impl<'a, Link, Store: 'a, Content> PreparedMessage<'a, Link, Store, Content> {
    pub fn new(store: Ref<'a, Store>, header: Header<Link>, content: Content,) -> Self {
        Self {
            store: store,
            header: header,
            content: content,
        }
    }
}

impl<'a, Link, Store, Content> PreparedMessage<'a, Link, Store, Content> {
    pub(crate) fn wrap(&self) -> Result<WrappedMessage<Link>> where
        Link: HasLink + AbsorbExternalFallback + Clone,
        <Link as HasLink>::Rel: Eq + SkipFallback,
        Store: 'a + LinkStore<<Link as HasLink>::Rel>,
        Header<Link>: ContentWrap<Store>,
        Content: ContentWrap<Store>,
    {
        let buf_size = {
            let mut ctx = sizeof::Context::new();
            self.header.sizeof(&mut ctx)?;
            self.content.sizeof(&mut ctx)?;
            ctx.get_size()
        };

        let mut buf = Trits::zero(buf_size);

        let spongos = {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            self.header.wrap(&*self.store, &mut ctx)?;
            self.content.wrap(&*self.store, &mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");

            ctx.spongos
        };

        Ok(WrappedMessage {
            spongos: spongos,
            message: TrinaryMessage {
                link: self.header.link.clone(),
                body: buf,
            }
        })
    }
}



impl<Link> TrinaryMessage<Link> where
    Link: Default + AbsorbExternalFallback,
{
    pub fn parse_header<'a>(&'a self) -> Result<PreparsedMessage<'a, Link>> {
        let mut ctx = unwrap::Context::new(self.body.slice());
        let mut header = Header::<Link>::default();
        let store = EmptyLinkStore::<Link, ()>::default();
        header.unwrap(&store, &mut ctx)?;

        Ok(PreparsedMessage {
            header: header,
            ctx: ctx,
        })
    }
}

pub(crate) trait ContentUnwrap<Store> {
    fn unwrap<'c, IS: io::IStream>(&mut self, store: &Store, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>>;
}

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, Link> {
    pub header: Header<Link>,
    pub(crate) ctx: unwrap::Context<TritSlice<'a>>,
}

impl<'a, Link> PreparsedMessage<'a, Link> {
    pub fn check_content_type(&self, content_type: &str) -> bool {
        (self.header.content_type.0).eq_str(content_type)
    }

    pub fn content_type(&self) -> String {
        (self.header.content_type.0).to_string()
    }

    pub(crate) fn unwrap<Store, Content>(mut self, store: &Store, mut content: Content) -> Result<UnwrappedMessage<Link, Content>> where
        Content: ContentUnwrap<Store>,
    {
        content.unwrap(&store, &mut self.ctx)?;
        // Discard what's left of `self.ctx.stream`
        Ok(UnwrappedMessage {
            link: self.header.link,
            content: content,
            spongos: self.ctx.spongos,
        })
    }
}

/// Result of wrapping the message.
pub struct UnwrappedMessage<Link, Content> {
    pub link: Link,
    pub content: Content,
    spongos: Spongos,
}

impl<Link, Content> UnwrappedMessage<Link, Content> where
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(mut self, mut store: RefMut<Store>, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<Content> where
        Store: LinkStore<<Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.link.rel(), self.spongos, info)?;
        Ok(self.content)
    }
}

pub mod header;
mod version;

pub use version::*;

