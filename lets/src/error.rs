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

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

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

impl From<SpongosError> for Error {
    fn from(error: SpongosError) -> Self {
        Self::Spongos(error)
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

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Self::External(error.into())
    }
}