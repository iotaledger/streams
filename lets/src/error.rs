//! Stream Errors

// Rust
use core::{array::TryFromSliceError, fmt::Debug};
use alloc::{boxed::Box, string::{FromUtf8Error, String}};

// 3rd-party
use hex::FromHexError;
use thiserror_no_std::Error;
// IOTA

use spongos::error::Error as SpongosError;

use crate::address::Address;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
#[cfg(feature = "did")]
pub enum IdentityError {
    #[error("Malformed {0}")]
    Core(identity_iota::core::Error),
    #[error("Malformed {0}")]
    Error(identity_iota::did::Error),
    #[error("Malformed {0}")]
    DIDError(identity_iota::did::DIDError),
    #[error("Malformed {0}")]
    IotaCore(identity_iota::iota_core::Error),
    #[error("Malformed {0}")]
    IotaClient(identity_iota::client::Error),
    #[error("Malformed {0}")]
    Other(String)
}

#[cfg(feature = "did")]
impl From<identity_iota::core::Error> for IdentityError {
    fn from(error: identity_iota::core::Error) -> Self {
        Self::Core(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::did::Error> for IdentityError {
    fn from(error: identity_iota::did::Error) -> Self {
        Self::Error(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::did::DIDError> for IdentityError {
    fn from(error: identity_iota::did::DIDError) -> Self {
        Self::DIDError(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::iota_core::Error> for IdentityError {
    fn from(error: identity_iota::iota_core::Error) -> Self {
        Self::IotaCore(error)
    }
}

#[cfg(feature = "did")]
impl From<identity_iota::client::Error> for IdentityError {
    fn from(error: identity_iota::client::Error) -> Self {
        Self::IotaClient(error)
    }
}

#[cfg(feature = "did")]
impl From<String> for IdentityError {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

#[derive(Debug, Error)]
/// Error type of the iota client crate.
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error("Malformed {0}: missing '{1}' for {2}")]
    Malformed(&'static str, &'static str, String),

    #[error("{0} is not encoded in {1} or the encoding is incorrect: {2:?}")]
    Encoding(&'static str, &'static str, Box<Error>),

    #[error("{0} must be {1} bytes long, but is {2} bytes long instead")]
    InvalidSize(&'static str, usize, u64),

    #[error("there was an issue with {0} the signature, cannot {1}")]
    Signature(&'static str, &'static str),

    #[cfg(feature = "did")]
    #[error("Encountered did issue {0}; Error: {1}")]
    Did(&'static str, IdentityError),

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

    #[error("Crypto error whilest doing {0}: {1}")]
    Crypto(&'static str, crypto::Error),

    #[error("External error: {0:?}")]
    External(anyhow::Error),

    /// Transport
    
    #[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
    #[error("Iota client error for {0}: {1}")]
    IotaClient(&'static str, iota_client::Error),

    #[error("Transport error for address {1}: {0}")]
    AddressError(&'static str, Address),

    #[error("message '{0}' not found in {1}")]
    MessageMissing(Address, &'static str),

    #[error("nonce is not in the range {0} for target score: {1}")]
    Nonce(&'static str, f64),
}

impl Error {
    #[cfg(feature = "did")]
    pub fn did<T: Into<IdentityError>>(did: &'static str, e: T) -> Self {
        Self::Did(did, e.into())
    }
}

impl From<SpongosError> for Error {
    fn from(error: SpongosError) -> Self {
        Self::Spongos(error)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Self::Encoding("string", "utf8", Box::new(Self::External(error.into())))
    }
}


impl From<FromHexError> for Error {
    fn from(error: FromHexError) -> Self {
        Self::External(error.into())
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::External(error.into())
    }
}

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Self::External(error.into())
    }
}