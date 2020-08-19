#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod hash;
pub mod prelude;
pub mod prng;
pub mod psk;
pub mod sponge;
