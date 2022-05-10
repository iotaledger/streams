// TODO: MOVE TO SPONGOS

// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA
use crypto::keys::x25519;

// Streams
use spongos::ddml::{
    commands::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
    types::NBytes,
};

// local

#[async_trait(?Send)]
pub trait ContentSizeof<T> {
    async fn sizeof(&mut self, content: &T) -> Result<&mut Self>;
}

#[async_trait(?Send)]
pub trait ContentWrap<T> {
    async fn wrap(&mut self, content: &mut T) -> Result<&mut Self>;
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
