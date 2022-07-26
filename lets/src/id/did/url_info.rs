// Rust
use alloc::{string::String, vec::Vec};

// 3rd-party
use anyhow::{anyhow, Result};

// IOTA
use identity_iota::{
    core::BaseEncoding,
    crypto::{Ed25519 as DIDEd25519, JcsEd25519, Named, Proof, ProofValue},
    did::{verifiable::VerifierOptions, DID as IdentityDID},
    iota_core::IotaDID,
};

use crate::id::did::DataWrapper;

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Bytes,
    },
    PRP,
};

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DIDUrlInfo {
    did: String,
    client_url: String,
    exchange_fragment: String,
    signing_fragment: String,
}

impl DIDUrlInfo {
    pub fn new<T: Into<String>>(did: IotaDID, client_url: T, exchange_fragment: T, signing_fragment: T) -> Self {
        Self {
            did: did.into_string(),
            client_url: client_url.into(),
            exchange_fragment: exchange_fragment.into(),
            signing_fragment: signing_fragment.into(),
        }
    }

    pub(crate) async fn verify(&self, signing_fragment: &str, signature_bytes: &[u8], hash: &[u8]) -> Result<()> {
        let did_url = IotaDID::parse(self.did())?.join(signing_fragment)?;
        let mut signature = Proof::new(JcsEd25519::<DIDEd25519>::NAME, did_url);
        signature.set_value(ProofValue::Signature(BaseEncoding::encode_base58(&signature_bytes)));

        let data = DataWrapper::new(&hash).with_signature(signature);

        let doc = super::resolve_document(&self).await?;
        doc.document
            .verify_data(&data, &VerifierOptions::new())
            .map_err(|e| anyhow!("There was an issue validating the signature: {}", e))?;

        Ok(())
    }

    pub(crate) fn did(&self) -> &str {
        &self.did
    }

    pub(crate) fn client_url(&self) -> &str {
        &self.client_url
    }

    pub(crate) fn exchange_fragment(&self) -> &str {
        &self.exchange_fragment
    }

    pub(crate) fn signing_fragment(&self) -> &str {
        &self.signing_fragment
    }

    pub(crate) fn did_mut(&mut self) -> &mut String {
        &mut self.did
    }

    pub(crate) fn client_url_mut(&mut self) -> &mut String {
        &mut self.client_url
    }

    pub(crate) fn exchange_fragment_mut(&mut self) -> &mut String {
        &mut self.exchange_fragment
    }

    pub(crate) fn signing_fragment_mut(&mut self) -> &mut String {
        &mut self.signing_fragment
    }
}

impl Mask<&DIDUrlInfo> for sizeof::Context {
    fn mask(&mut self, url_info: &DIDUrlInfo) -> Result<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<OS, F> Mask<&DIDUrlInfo> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, url_info: &DIDUrlInfo) -> Result<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<IS, F> Mask<&mut DIDUrlInfo> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, url_info: &mut DIDUrlInfo) -> Result<&mut Self> {
        let mut did_bytes = Vec::new();
        let mut client_url = Vec::new();
        let mut exchange_fragment_bytes = Vec::new();
        let mut signing_fragment_bytes = Vec::new();
        self.mask(Bytes::new(&mut did_bytes))?
            .mask(Bytes::new(&mut client_url))?
            .mask(Bytes::new(&mut exchange_fragment_bytes))?
            .mask(Bytes::new(&mut signing_fragment_bytes))?;

        *url_info.did_mut() = String::from_utf8(did_bytes)?;
        *url_info.client_url_mut() = String::from_utf8(client_url)?;
        *url_info.exchange_fragment_mut() = String::from_utf8(exchange_fragment_bytes)?;
        *url_info.signing_fragment_mut() = String::from_utf8(signing_fragment_bytes)?;
        Ok(self)
    }
}
