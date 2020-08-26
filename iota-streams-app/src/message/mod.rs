use anyhow::Result;

use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
};

use iota_streams_core_edsig::key_exchange::x25519;

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
    fn link_from(&mut self, arg: &From, pk: x25519::PublicKey, multi_branching: u8, seq: usize) -> Link;

    /// Derive a new link and construct a header with given content type.
    fn header_from(
        &mut self,
        arg: &From,
        pk: x25519::PublicKey,
        multi_branching: u8,
        seq: usize,
        content_type: &str,
    ) -> header::Header<Link>;
    // {
    // header::Header::new_with_type(self.link_from(arg), content_type)
    // }
}

pub trait ContentWrap<F, Store> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>>;
    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>>;
}

pub trait ContentUnwrap<F, Store> {
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>;
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
