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
pub trait ContentSizeof<T> {
    async fn sizeof(&mut self, content: &T) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentWrap<T> {
    async fn wrap(&mut self, content: &mut T) -> Result<&mut Self>
    where
        T: 'async_trait;
}

#[async_trait(?Send)]
pub trait ContentUnwrap<T> {
    async fn unwrap(&mut self, content: &mut T) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentSignSizeof<T> {
    async fn sign_sizeof(&mut self, ctx: &T) -> Result<&mut Self>;
}

// TODO: MAKE SURE 'a is not needed in the traits that don't yet have it
#[async_trait(?Send)]
pub trait ContentSign<T> {
    async fn sign(&mut self, signer: &T) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentVerify<T> {
    async fn verify(&mut self, verifier: &T) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentEncryptSizeOf<T> {
    async fn encrypt_sizeof(&mut self, recipient: &T, exchange_key: &[u8], key: &[u8]) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentEncrypt<T> {
    async fn encrypt(&mut self, recipient: &T, exchange_key: &[u8], key: &[u8]) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentDecrypt<T> {
    async fn decrypt(&mut self, recipient: &T, exchange_key: &[u8], key: &mut [u8]) -> Result<&mut Self>;
}
