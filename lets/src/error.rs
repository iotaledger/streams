//! Stream Errors

use core::{fmt::Debug, array::TryFromSliceError};

use alloc::{boxed::Box, string::FromUtf8Error};

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
    #[error("Malformed {0} string: missing '{1}'")]
    Malformed(&'static str, &'static str),

    #[error("{0} is not encoded in {1} or the encoding is incorrect: {2:?}")]
    Encoding(&'static str, &'static str, Box<Error>),

    #[error("{0} must be {1} bytes long, but is {2} bytes long instead")]
    InvalidSize(&'static str, usize, u64),

    #[error("Invalid {0} type. Found '{1}', expected '{2}'")]
    InvalidType(&'static str, usize, u8),

    #[error("there was an issue with {0} the signature, cannot {1}")]
    Signature(&'static str, &'static str),

    #[error("Internal Spongos error: {0}")]
    Spongos(SpongosError),

    #[error("External error: {0:?}")]
    External(anyhow::Error),

    /// Transport

    #[error("Transport error for address {1}: {0}")]
    AddressError(&'static str, Address),

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