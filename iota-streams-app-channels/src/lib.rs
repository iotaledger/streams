//! Implementation of Streams Channel Application.

#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// Channel Messages.
pub mod message;

/// Author and Subscriber API.
pub mod api;
