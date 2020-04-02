//! Trinary & binary slices, buffers, encodings and conversions.

pub mod convert;
pub mod slice;
pub mod tbits;
#[cfg(test)]
pub(crate) mod tests;
pub mod word;

pub use convert::*;
pub use slice::*;
pub use tbits::*;

pub mod binary;
pub mod trinary;

/*
pub mod b1t1;
pub mod b1t5;
pub mod b8t32;
 */
