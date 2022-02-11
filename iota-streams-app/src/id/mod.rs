pub mod identifier;
pub mod user_identity;

pub use identifier::*;
pub use user_identity::*;

#[cfg(feature = "did")]
pub mod data_wrapper;
#[cfg(feature = "did")]
pub use data_wrapper::*;

#[cfg(feature = "did")]
use iota_streams_core::prelude::digest::generic_array::{
    typenum::U32,
    GenericArray,
};

#[cfg(feature = "did")]
pub type DIDSize = U32;

#[cfg(feature = "did")]
pub type DIDWrap = GenericArray<u8, DIDSize>;

#[cfg(feature = "did")]
pub const DID_CORE: &str = "did:iota:";

#[cfg(feature = "did")]
pub type DIDClient = identity::iota::Client;
