mod identifier;
mod user_identity;

pub use identifier::Identifier;
pub use user_identity::UserIdentity;

#[cfg(feature = "did")]
mod did;

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
