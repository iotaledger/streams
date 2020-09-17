use anyhow::Result;

use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
};

/// Type of "absolute" links. For http it's the absolute URL.
pub trait HasLink: Sized + Default + Clone + Eq {
    /// Type of "base" links. For http it's domain name.
    type Base: Default + Clone;

    /// Get base part of the link.
    fn base(&self) -> &Self::Base;

    /// Type of "relative" links. For http it's URL path.
    type Rel: Default + Clone;

    /// Get relative part of the link.
    fn rel(&self) -> &Self::Rel;

    /// Construct absolute link from base and relative parts.
    fn from_base_rel(base: &Self::Base, rel: &Self::Rel) -> Self;
}

/// Abstraction-helper to generate message links.
pub trait LinkGenerator<Link, From> {
    /// Derive a new link using an arg.
    fn link_from(&mut self, arg: From) -> Link;

    /// Derive a new link and construct a header with given content type.
    fn header_from(&mut self, arg: From, content_type: u8, payload_length: usize, seq_num: usize) -> HDF<Link> {
        HDF::new_with_fields(
            self.link_from(arg),
            content_type,
            payload_length,
            seq_num,
        )
    }
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

pub mod hdf;
pub use hdf::HDF;
pub mod pcf;
pub use pcf::PCF;

mod version;
pub use version::*;

mod prepared;
pub use prepared::*;
mod wrapped;
pub use wrapped::*;
mod binary;
pub use binary::*;
mod preparsed;
pub use preparsed::*;
mod unwrapped;
pub use unwrapped::*;
