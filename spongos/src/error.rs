use core::{fmt::{Debug, Display}, array::TryFromSliceError};

use thiserror_no_std::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    //////////
    // Generic
    //////////
    #[error("Size of vec/array does not match (expected: {0}, found: {1})")]
    LengthMismatch(usize, usize),

    //////////
    // DDML Wrap/Unwrap
    //////////
    #[error("here was an issue with the calculated signature, cannot unwrap message")]
    SignatureMismatch,
    #[error("Failure to generate ed25519 public key: {0:?}")]
    PublicKeyGenerationFailure(crypto::Error),
    #[error("Failed to generate slice from reference: {0:?}")]
    SliceMismatch(TryFromSliceError),
    #[error("Integrity violation. Bad MAC")]
    BadMac,

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
}

impl Error {
    pub(crate) fn wrap<T>(&self, src: &T) -> anyhow::Error
    where
        T: Display + Debug,
    {
        anyhow::anyhow!("\n\tStreams Error: {}\n\t\tCause: {:?}", self, src)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(error: TryFromSliceError) -> Self {
        Self::SliceMismatch(error)
    }
}

