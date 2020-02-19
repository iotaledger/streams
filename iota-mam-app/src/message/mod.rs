use failure::{ensure, Fallible};
use std::cell::{Ref, RefMut};
use std::string::ToString;

use iota_mam_core::{
    spongos::Spongos,
    trits::{TritSlice, Trits},
};
use iota_mam_protobuf3::{
    command::{sizeof, unwrap, wrap},
    io,
    types::*,
};

/// Type of "absolute" links. For http it's the absolute URL.
pub trait HasLink: Sized {
    /// Type of "base" links. For http it's domain name.
    type Base;

    /// Get base part of the link.
    fn base(&self) -> &Self::Base;

    /// Type of "relative" links. For http it's URL path.
    type Rel;

    /// Get relative part of the link.
    fn rel(&self) -> &Self::Rel;

    /// Construct absolute link from base and relative parts.
    fn from_base_rel(base: &Self::Base, rel: &Self::Rel) -> Self;
}

/// Abstraction-helper to generate message links.
pub trait LinkGenerator<Link, From> {
    /// Derive a new link using an arg.
    fn link_from(&mut self, arg: &From) -> Link;

    /// Derive a new link and construct a header with given content type.
    fn header_from(&mut self, arg: &From, content_type: &str) -> header::Header<Link> {
        header::Header::new_with_type(self.link_from(arg), content_type)
    }
}

/// Trinary network Message representation.
#[derive(Clone, Debug)]
pub struct TrinaryMessage<AbsLink> {
    /// Link -- message address.
    pub link: AbsLink,

    /// Message body -- header + content.
    pub body: Trits,
}

impl<AbsLink> TrinaryMessage<AbsLink> {
    pub fn new(link: AbsLink, body: Trits) -> Self {
        Self { link, body }
    }
    pub fn link(&self) -> &AbsLink {
        &self.link
    }
}

pub mod header;
use header::Header;

pub trait ContentWrap<Store> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Fallible<&'c mut sizeof::Context>;
    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<OS>,
    ) -> Fallible<&'c mut wrap::Context<OS>>;
}

/// Result of wrapping the message.
pub struct WrappedMessage<Link> {
    pub message: TrinaryMessage<Link>,
    spongos: Spongos,
}

impl<Link> WrappedMessage<Link>
where
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(
        mut self,
        mut store: RefMut<Store>,
        info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info,
    ) -> Fallible<TrinaryMessage<Link>>
    where
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
    pub fn new(store: Ref<'a, Store>, header: Header<Link>, content: Content) -> Self {
        Self {
            store: store,
            header: header,
            content: content,
        }
    }
}

impl<'a, Link, Store, Content> PreparedMessage<'a, Link, Store, Content> {
    pub fn wrap(&self) -> Fallible<WrappedMessage<Link>>
    where
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
            },
        })
    }
}

impl<Link> TrinaryMessage<Link>
where
    Link: Clone + AbsorbExternalFallback,
{
    pub fn parse_header<'a>(&'a self) -> Fallible<PreparsedMessage<'a, Link>> {
        let mut ctx = unwrap::Context::new(self.body.slice());
        let mut header = Header::<Link>::new(self.link().clone());
        let store = EmptyLinkStore::<Link, ()>::default();
        header.unwrap(&store, &mut ctx)?;

        Ok(PreparsedMessage {
            header: header,
            ctx: ctx,
        })
    }
}

pub trait ContentUnwrap<Store> {
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<IS>,
    ) -> Fallible<&'c mut unwrap::Context<IS>>;
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

    pub fn unwrap<Store, Content>(
        mut self,
        store: &Store,
        mut content: Content,
    ) -> Fallible<UnwrappedMessage<Link, Content>>
    where
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

impl<Link, Content> UnwrappedMessage<Link, Content>
where
    Link: HasLink,
{
    /// Save link for the current wrapped message and accociated info into the store.
    pub fn commit<Store>(
        mut self,
        mut store: RefMut<Store>,
        info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info,
    ) -> Fallible<Content>
    where
        Store: LinkStore<<Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.link.rel(), self.spongos, info)?;
        Ok(self.content)
    }
}

mod version;
pub use version::*;
