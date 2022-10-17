// TODO: MOVE TO SPONGOS?

// Rust
use alloc::boxed::Box;

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams

// Local
use spongos::error::Result;

/// Used to determine the encoding size of the object `T`
#[async_trait(?Send)]
pub trait ContentSizeof<T> {
    async fn sizeof(&mut self, content: &T) -> Result<&mut Self>;
}

/// Used for encoding the object `T` into a `Context` stream
#[async_trait(?Send)]
pub trait ContentWrap<T> {
    async fn wrap(&mut self, content: &mut T) -> Result<&mut Self>;
}

/// Used for decoding the object `T` from a `Context` stream
#[async_trait(?Send)]
pub trait ContentUnwrap<T> {
    async fn unwrap(&mut self, content: &mut T) -> Result<&mut Self>;
}

/// Used to determine the encoding size of the signature operation for object `T`
#[async_trait(?Send)]
pub trait ContentSignSizeof<T> {
    async fn sign_sizeof(&mut self, ctx: &T) -> Result<&mut Self>;
}

/// Used to sign the `Context` `Spongos` state hash and encode the signature into the `Context`
/// stream
#[async_trait(?Send)]
pub trait ContentSign<T> {
    async fn sign(&mut self, signer: &T) -> Result<&mut Self>;
}

/// Used to authenticate the signature from the `Context` stream
#[async_trait(?Send)]
pub trait ContentVerify<T> {
    async fn verify(&mut self, verifier: &T) -> Result<&mut Self>;
}

/// Used to determine the encoding size of the encryption operation for a key slice for recipient
/// `T`
#[async_trait(?Send)]
pub trait ContentEncryptSizeOf<T> {
    async fn encrypt_sizeof(&mut self, recipient: &T, key: &[u8]) -> Result<&mut Self>;
}

/// Used to encrypt a key slice for recipient `T`
#[async_trait(?Send)]
pub trait ContentEncrypt<T> {
    async fn encrypt(&mut self, recipient: &T, key: &[u8]) -> Result<&mut Self>;
}

/// Used to decrypt a key slice for recipient `T`
#[async_trait(?Send)]
pub trait ContentDecrypt<T> {
    async fn decrypt(&mut self, recipient: &T, key: &mut [u8]) -> Result<&mut Self>;
}
