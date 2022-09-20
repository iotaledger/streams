mod data_wrapper;
mod did;
mod url_info;

pub use did::{DIDInfo, DID};
pub use url_info::DIDUrlInfo;

pub(crate) use data_wrapper::DataWrapper;
pub(crate) use did::resolve_document;
