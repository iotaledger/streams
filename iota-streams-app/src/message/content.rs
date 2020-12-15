use iota_streams_core::Result;

use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
};

pub trait ContentSizeof<F> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>>;
}

pub trait ContentWrap<F, Store>: ContentSizeof<F> {
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
