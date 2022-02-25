pub mod identifier;
pub mod user_identity;

pub use identifier::Identifier;
pub use user_identity::UserIdentity;

#[cfg(feature = "did")]
pub mod did;

#[cfg(feature = "did")]
pub use did::{
    DIDClient,
    DIDImpl,
    DIDInfo,
    DIDSize,
    DIDWrap,
    DataWrapper,
    DID_CORE,
};
