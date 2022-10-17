/// Wrapper around data for signature validation via `DID`
mod data_wrapper;
/// Base `DID` functionality and types
mod did;
/// Details required for `DID` resolution
mod url_info;

pub use did::{DIDInfo, DID};
pub use url_info::DIDUrlInfo;

pub(crate) use data_wrapper::DataWrapper;
pub(crate) use did::resolve_document;
