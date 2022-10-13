use core::{array::TryFromSliceError, fmt::Debug};

use alloc::string::String;
use thiserror_no_std::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
/// Error type of the Spongos crate.
pub enum Error {
    //////////
    // Generic
    //////////
    #[error("Size of vec/array does not match (expected: {0}, found: {1})")]
    LengthMismatch(usize, usize),

    //////////
    // DDML Wrap/Unwrap
    //////////
    #[error("There was an issue with the calculated signature, cannot unwrap message")]
    SignatureMismatch,
    #[error("Failure to generate ed25519 public key: {0:?}")]
    PublicKeyGenerationFailure(crypto::Error),
    #[error("Failed to generate slice from reference: {0:?}")]
    SliceMismatch(TryFromSliceError),
    #[error("Integrity violation. Bad MAC")]
    BadMac,

    #[error("Failed to \"{0}\" for {1}. Reason: {2}")]
    InvalidAction(&'static str, String, String),

    #[error("{1} is not a valid {0} option")]
    InvalidOption(&'static str, u8),

    #[error("{0} version '{1}' not supported")]
    Version(&'static str, u8),

    #[error("Reserved area was not empty: {0}")]
    Reserved(&'static str),

    //////////
    // DDML IO
    //////////
    #[error("Not enough space allocated for output stream (expected: {0}, found: {1})")]
    StreamAllocationExceededOut(usize, usize),
    #[error("Not enough space allocated for input stream (expected: {0}, found: {1})")]
    StreamAllocationExceededIn(usize, usize),

    #[error("Context failed to perform the message command \"{0}\"; Error: {1}")]
    Context(&'static str, String),

    #[error("{0}")]
    External(anyhow::Error),
}

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Self::SliceMismatch(error)
    }
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Self::External(error)
    }
}
