use failure::Fallible;

use iota_streams_protobuf3::{
    command::{sizeof, unwrap, wrap},
    io,
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
pub trait LinkGenerator<TW, Link, From> {
    /// Derive a new link using an arg.
    fn link_from(&mut self, arg: &From) -> Link;

    /// Derive a new link and construct a header with given content type.
    fn header_from(&mut self, arg: &From, content_type: &str) -> header::Header<TW, Link>;
    /*
    {
        header::Header::new_with_type(self.link_from(arg), content_type)
    }
     */
}

pub trait ContentWrap<TW, F, Store> {
    fn sizeof<'c>(
        &self,
        ctx: &'c mut sizeof::Context<TW, F>,
    ) -> Fallible<&'c mut sizeof::Context<TW, F>>;
    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Fallible<&'c mut wrap::Context<TW, F, OS>>;
}

pub trait ContentUnwrap<TW, F, Store> {
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Fallible<&'c mut unwrap::Context<TW, F, IS>>;
}

pub mod header;
use header::Header;
mod version;
pub use version::*;

mod prepared;
pub use prepared::*;
mod wrapped;
pub use wrapped::*;
mod tbinary;
pub use tbinary::*;
mod preparsed;
pub use preparsed::*;
mod unwrapped;
pub use unwrapped::*;
