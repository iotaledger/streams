use identity::{
    crypto::{
        SetSignature,
        Signature,
        TrySignature,
        TrySignatureMut,
    },
    did::{
        MethodUriType,
        TryMethod,
    },
};
use iota_streams_core::prelude::Vec;
use serde::Serialize;

#[derive(Serialize)]
pub struct DataWrapper {
    pub data: Vec<u8>,
    pub signature: Option<Signature>,
}

impl TrySignature for DataWrapper {
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

impl TrySignatureMut for DataWrapper {
    fn signature_mut(&mut self) -> Option<&mut Signature> {
        self.signature.as_mut()
    }
}

impl SetSignature for DataWrapper {
    fn set_signature(&mut self, signature: Signature) {
        self.signature = Some(signature)
    }
}

impl TryMethod for DataWrapper {
    const TYPE: MethodUriType = MethodUriType::Absolute;
}
