// TODO: MOVE TO SPONGOS
use alloc::boxed::Box;

use anyhow::Result;
use async_trait::async_trait;
// TODO: REMOVE
// use generic_array::ArrayLength;

use spongos::ddml::{
    commands::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
    types::NBytes,
};

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     Result,
// };

// use iota_streams_ddml::{
//     command::{
//         sizeof,
//         unwrap,
//         wrap,
//     },
//     io,
//     types::{
//         ArrayLength,
//         NBytes,
//     },
// };

#[async_trait(?Send)]
pub trait ContentSizeof<'a> {
    async fn sizeof<'b>(&'a self, ctx: &'b mut sizeof::Context) -> Result<&'b mut sizeof::Context>;
}

#[async_trait(?Send)]
pub trait ContentWrap<'a, F, OS>: ContentSizeof<'a> {
    async fn wrap<'b>(&'a self, ctx: &'b mut wrap::Context<F, OS>) -> Result<&'b mut wrap::Context<F, OS>>;
}

#[async_trait(?Send)]
pub trait ContentUnwrap<'a, F, IS> {
    async fn unwrap<'b>(&'a mut self, ctx: &'b mut unwrap::Context<F, IS>) -> Result<&'b mut unwrap::Context<F, IS>>;
}

#[async_trait(?Send)]
pub trait ContentSignSizeof {
    async fn sign_sizeof<'a>(&self, ctx: &'a mut sizeof::Context) -> Result<&'a mut sizeof::Context>;
}

// TODO: MAKE SURE 'a is not needed in the traits that don't yet have it 
#[async_trait(?Send)]
pub trait ContentSign<F, OS> {
    async fn sign<'a>(&self, ctx: &'a mut wrap::Context<F, OS>) -> Result<&'a mut wrap::Context<F, OS>>;
}

#[async_trait(?Send)]
pub trait ContentVerify<F, IS> {
    async fn verify<'a>(&self, ctx: &'a mut unwrap::Context<F, IS>) -> Result<&'a mut unwrap::Context<F, IS>>;
}

#[async_trait(?Send)]
pub trait ContentEncryptSizeOf {
    async fn encrypt_sizeof<'a>(
        &self,
        ctx: &'a mut sizeof::Context,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut sizeof::Context>;
}

#[async_trait(?Send)]
pub trait ContentEncrypt<F, OS> {
    async fn encrypt<'a>(
        &self,
        ctx: &'a mut wrap::Context<F, OS>,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut wrap::Context<F, OS>>;
}

#[async_trait(?Send)]
pub trait ContentDecrypt<F, IS> {
    async fn decrypt<'a>(
        &self,
        ctx: &'a mut unwrap::Context<F, IS>,
        exchange_key: &'a [u8],
        key: &'a mut [u8],
    ) -> Result<&'a mut unwrap::Context<F, IS>>;
}