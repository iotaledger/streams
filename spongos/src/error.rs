use core::fmt::{
    Debug,
    Display,
};

use displaydoc::Display;

#[derive(Display, Debug)]
pub enum Error {
    //////////
    // Generic
    //////////
    /// Size of vec/array does not match (expected: {0}, found: {1})
    LengthMismatch(usize, usize),

    //////////
    // DDML Wrap/Unwrap
    //////////
    /// There was an issue with the calculated signature, cannot unwrap message
    SignatureMismatch,
    /// Failure to generate ed25519 public key
    PublicKeyGenerationFailure,
    /// Integrity violation. Bad MAC
    BadMac,

    //////////
    // DDML IO
    //////////
    /// Not enough space allocated for output stream (expected: {0}, found: {1})
    StreamAllocationExceededOut(usize, usize),
    /// Not enough space allocated for input stream (expected: {0}, found: {1})
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
