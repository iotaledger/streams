use iota_streams_core::{
    async_trait,
    prelude::Box,
    Result,
};

use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
};

#[async_trait(?Send)]
pub trait ContentSizeof<F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>>;
}

#[async_trait(?Send)]
pub trait ContentWrap<F, Store>: ContentSizeof<F> {
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>>;
}

#[async_trait(?Send)]
pub trait ContentSign<F, OS: io::OStream> {
    async fn sign<'c>(
        &self,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>>;
}

#[async_trait(?Send)]
pub trait ContentUnwrap<F, Store> {
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>;
}


#[async_trait(?Send)]
pub trait ContentVerify<'a, F, IS: io::IStream> {
    async fn verify<'c>(
        &self,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>;
}

#[async_trait(?Send)]
pub trait ContentUnwrapNew<F, Store>
where
    Self: Sized,
{
    async fn unwrap_new<'c, IS: io::IStream>(
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)>;
}
