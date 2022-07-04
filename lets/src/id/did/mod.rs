use alloc::string::ToString;
use identity_iota::{
    client::{Client as DIDClient, ResolvedIotaDocument},
    iota_core::IotaDID,
};

use anyhow::Result;

pub(crate) async fn resolve_document(url_info: &DIDUrlInfo) -> Result<ResolvedIotaDocument> {
    let did_url = IotaDID::parse(url_info.did().to_string())?;
    let doc = DIDClient::builder()
        .network(did_url.network()?)
        .primary_node(url_info.client_url(), None, None)?
        .build()
        .await?
        .read_document(&did_url)
        .await?;
    Ok(doc)
}

mod did;

pub use did::{DIDInfo, DIDUrlInfo, DID};

pub(crate) use did::DataWrapper;

