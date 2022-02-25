pub mod identifier;
pub mod user_identity;

pub use identifier::Identifier;
pub use user_identity::UserIdentity;

#[cfg(feature = "did")]
pub mod did;

#[cfg(feature = "did")]
pub use did::{
    DataWrapper,
    DID_CORE,
    DIDInfo,
    DIDImpl,
    DIDClient,
    DIDSize,
    DIDWrap,
};