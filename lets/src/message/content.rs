// TODO: MOVE TO SPONGOS?

// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA

// Streams

// Local

#[async_trait]
pub trait ContentSizeof<T> {
    async fn sizeof(&mut self, content: &T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentWrap<T> {
    async fn wrap(&mut self, content: &mut T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentUnwrap<T> {
    async fn unwrap(&mut self, content: &mut T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentSignSizeof<T> {
    async fn sign_sizeof(&mut self, ctx: &T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentSign<T> {
    async fn sign(&mut self, signer: &T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentVerify<T> {
    async fn verify(&mut self, verifier: &T) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentEncryptSizeOf<T> {
    async fn encrypt_sizeof(&mut self, recipient: &T, exchange_key: &[u8], key: &[u8]) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentEncrypt<T> {
    async fn encrypt(&mut self, recipient: &T, exchange_key: &[u8], key: &[u8]) -> Result<&mut Self>;
}

#[async_trait]
pub trait ContentDecrypt<T> {
    async fn decrypt(&mut self, recipient: &T, exchange_key: &[u8], key: &mut [u8]) -> Result<&mut Self>;
}
