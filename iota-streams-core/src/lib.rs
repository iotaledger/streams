#![no_std]
//#![feature(generic_associated_types)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

// Stub used in tests & examples.
// Macros are exported at crate root level, that's why it's defined here, not in `prelude` mod.
#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! println {
    () => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! print {
    () => {};
    ($($arg:tt)*) => {};
}

// Reexport macro at the same level as `no_std`.
#[cfg(feature = "std")]
pub use std::println;

#[cfg(feature = "std")]
pub use std::print;

#[cfg(not(feature = "std"))]
pub use alloc::format;

#[cfg(feature = "std")]
pub use std::format;

pub mod hash;
pub mod prelude;
pub mod prng;
pub mod psk;
pub mod sponge;
