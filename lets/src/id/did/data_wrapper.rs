// 3rd-party
use serde::Serialize;

use identity_iota::{
    crypto::{GetSignature, GetSignatureMut, Proof, SetSignature},
    did::{MethodUriType, TryMethod},
};

#[derive(Serialize)]
pub(crate) struct DataWrapper<'a> {
    data: &'a [u8],
    signature: Option<Proof>,
}

impl<'a> DataWrapper<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, signature: None }
    }

    pub(crate) fn with_signature(mut self, signature: Proof) -> Self {
        self.signature = Some(signature);
        self
    }

    pub(crate) fn into_signature(self) -> Option<Proof> {
        self.signature
    }
}

impl<'a> GetSignature for DataWrapper<'a> {
    fn signature(&self) -> Option<&Proof> {
        self.signature.as_ref()
    }
}

impl<'a> GetSignatureMut for DataWrapper<'a> {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.signature.as_mut()
    }
}

impl<'a> SetSignature for DataWrapper<'a> {
    fn set_signature(&mut self, signature: Proof) {
        self.signature = Some(signature)
    }
}

impl<'a> TryMethod for DataWrapper<'a> {
    const TYPE: MethodUriType = MethodUriType::Absolute;
}
