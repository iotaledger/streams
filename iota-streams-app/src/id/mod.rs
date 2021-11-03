#[cfg(feature = "use-did")]
pub use data_wrapper::*;

pub mod identifier;
pub mod keys;

pub use identifier::*;
pub use keys::*;

#[cfg(feature = "use-did")]
use iota_streams_core::prelude::digest::generic_array::{
    typenum::U32,
    GenericArray,
};

#[cfg(feature = "use-did")]
pub mod data_wrapper;

#[cfg(feature = "use-did")]
pub const DID_SIZE: usize = 32;

#[cfg(feature = "use-did")]
pub type DIDSize = U32;

#[cfg(feature = "use-did")]
pub type DIDWrap = GenericArray<u8, DIDSize>;

#[cfg(feature = "use-did")]
pub const DID_CORE: &str = "did:iota:";
