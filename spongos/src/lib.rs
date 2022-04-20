#![no_std]

// Spongos requires heap allocation for Vectors and Strings
#[cfg_attr(not(feature = "std"), macro_use)]
extern crate alloc;

// Spongos requires the feature "std" for the Dump DDML command
#[cfg(feature = "std")]
#[macro_use]
extern crate std;

// TODO: REMOVE
// // Stub used in tests & examples.
// // Macros are exported at crate root level, that's why it's defined here, not in `prelude` mod.
// #[cfg(not(any(target_arch = "wasm32", feature = "std")))]
// #[macro_export]
// macro_rules! println {
//     () => {{}};
//     ($($arg:tt)*) => {{}};
// }

// #[cfg(not(feature = "std"))]
// #[macro_export]
// macro_rules! print {
//     () => {{}};
//     ($($arg:tt)*) => {{}};
// }

// #[cfg(target_arch = "wasm32")]
// pub use web_sys;

// // You need to override `std::println` imported by default with
// // `use iota_streams::core::println;` in your mod.
// #[cfg(target_arch = "wasm32")]
// #[macro_export]
// macro_rules! println {
//     ( $( $arg:tt )* ) => {
//         $crate::web_sys::console::log_1(&$crate::format!( $( $arg )* ).into())
//     }
// }

// // Reexport macro at the same level as `no_std`.
// #[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
// pub use std::println;

// #[cfg(feature = "std")]
// pub use std::print;

// #[cfg(not(feature = "std"))]
// pub use alloc::format;

// #[cfg(feature = "std")]
// pub use std::format;

// #[cfg(not(feature = "err-location-log"))]
// pub const LOCATION_LOG: bool = false;

// #[cfg(feature = "err-location-log")]
// pub const LOCATION_LOG: bool = true;

mod error;
use error::Error;

// mod prelude;
// TODO: MOVE TO LETS
// mod psk;
mod core;
pub mod ddml;

// TODO: REMOVE
// pub use errors::{
//     error_handler::*,
//     error_messages::*,
// };

pub use crate::core::{
    // prng::Prng,
    spongos::Spongos,
    prp::PRP,
    prng::SpongosRng,
    prp::keccak::KeccakF1600
};
