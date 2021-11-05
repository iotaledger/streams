use core::ptr::{
    null,
};

use iota_streams::{
    app::{
        cstr_core::CStr,
        cty::{c_char, uint8_t},
        id::create_identity,
    },
    core::{
        Error,
        wrapped_err,
        WrappedError,
        Errors::DIDRetrievalFailure,
        prelude::{ToString, String},
        iota_identity::{
            core::{decode_b58, encode_b58},
            crypto::{
                KeyType,
                KeyPair,
                PublicKey,
                PrivateKey,
            },
            iota::{
                Client as DIDClient,
                IotaDID,
                Network as ApiDIDNetwork
            },

        },
        Result,
    }
};
use crate::{safe_into_ptr, run_async, Err, safe_into_mut_ptr, safe_drop_ptr};
pub use core::convert::TryFrom;
pub use iota_streams::app::id::DIDInfo as ApiDIDInfo;

pub struct DIDInfo {
    did: String,
    key_fragment: String,
    url: String,
    network: DIDNetwork,
}

#[derive(Clone)]
pub enum DIDNetwork {
    Mainnet,
    Devnet,
}

#[derive(Clone)]
pub struct DIDKeypair {
    public: String,
    private: String,
}

pub struct DIDInfoWrapper {
    info: DIDInfo,
    keypair: DIDKeypair,
}

impl DIDKeypair {
    fn new(public_key: &str, private_key: &str) -> DIDKeypair {
        DIDKeypair {
            public: public_key.to_string(),
            private: private_key.to_string(),
        }
    }

    pub fn public(&self) -> &str {
        &self.public
    }

    pub fn private(&self) -> &str {
        &self.private
    }
}

impl From<&DIDKeypair> for KeyPair {
    fn from(kp: &DIDKeypair) -> Self {
        KeyPair::from((
            KeyType::Ed25519,
            PublicKey::from(decode_b58(&kp.public()).unwrap()),
            PrivateKey::from(decode_b58(&kp.private()).unwrap()),
        ))
    }
}

impl From<KeyPair> for DIDKeypair {
    fn from(kp: KeyPair) -> Self {
        DIDKeypair::new(
            &encode_b58(kp.public()),
            &encode_b58(kp.private())
        )
    }
}

impl From<DIDNetwork> for ApiDIDNetwork {
    fn from(n: DIDNetwork) -> Self {
        match n {
            DIDNetwork::Mainnet => ApiDIDNetwork::Mainnet,
            DIDNetwork::Devnet => ApiDIDNetwork::Devnet,
        }
    }
}

impl DIDInfo {
    fn new(did: &str, key_fragment: &str, url: &str, network: DIDNetwork) -> DIDInfo {
        DIDInfo {
            did: did.to_string(),
            key_fragment: key_fragment.to_string(),
            url: url.to_string(),
            network,
        }
    }

    pub fn did(&self) -> String {
        self.did.clone()
    }

    pub fn key_fragment(&self) -> String {
        self.key_fragment.clone()
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn network(&self) -> DIDNetwork {
        self.network.clone()
    }

    pub fn clone(&self) -> DIDInfo {
        DIDInfo {
            did: self.did.clone(),
            key_fragment: self.key_fragment.clone(),
            url: self.url.clone(),
            network: self.network.clone(),
        }
    }
}

impl DIDInfoWrapper {
    pub fn new(info: DIDInfo, keypair: DIDKeypair) -> DIDInfoWrapper {
        DIDInfoWrapper { info, keypair }
    }

    pub fn info(&self) -> DIDInfo {
        self.info.clone()
    }

    pub fn keypair(&self) -> DIDKeypair {
        self.keypair.clone()
    }
}

impl TryFrom<&DIDInfo> for ApiDIDInfo {
    type Error = Error;

    fn try_from(info: &DIDInfo) -> Result<ApiDIDInfo> {
        IotaDID::parse(&info.did)
            .map_or_else(
                |err| Err(wrapped_err(DIDRetrievalFailure, WrappedError(err))),
                |did| {
                    let builder = DIDClient::builder()
                        .network(info.network.clone().into())
                        .primary_node(&info.url, None, None)
                        .unwrap();
                    run_async(builder.build())
                        .map_or_else(
                            |err| Err(wrapped_err(DIDRetrievalFailure, WrappedError(err))),
                            |client|
                                Ok(ApiDIDInfo {
                                    did: Some(did),
                                    key_fragment: info.key_fragment(),
                                    did_client: client,
                                    url: info.url.clone()
                                }))
                })
    }
}


#[no_mangle]
pub unsafe extern "C" fn new_did_info(
    did: *const c_char,
    key_fragment: *const c_char,
    url: *const c_char,
    network: uint8_t,
) -> *const DIDInfo {
    CStr::from_ptr(did).to_str().map_or(null(), |did_str| {
        CStr::from_ptr(key_fragment).to_str().map_or(null(), |fragment_str| {
            CStr::from_ptr(url).to_str().map_or(null(), |url_str| {
                let network = if network == 0 { DIDNetwork::Mainnet } else { DIDNetwork::Devnet };
                safe_into_ptr(DIDInfo::new(
                    did_str,
                    fragment_str,
                    url_str,
                    network
                ))
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn new_did_keypair(
    public: *const c_char,
    private: *const c_char,
) -> *const DIDKeypair {
    CStr::from_ptr(public).to_str().map_or(null(), |public_key| {
        CStr::from_ptr(private).to_str().map_or(null(), |private_key| {
            safe_into_ptr(DIDKeypair::new(public_key, private_key))
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_info_wrapper_keypair(wrapper: *const DIDInfoWrapper) -> *const DIDKeypair {
    wrapper.as_ref().map_or(null(), |wrapper| {
        safe_into_ptr(wrapper.keypair())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_info_wrapper_info(wrapper: *const DIDInfoWrapper) -> *const DIDInfo {
    wrapper.as_ref().map_or(null(), |wrapper| {
        safe_into_ptr(wrapper.info())
    })
}

#[no_mangle]
pub unsafe extern "C" fn create_new_identity(wrapper: *mut *const DIDInfoWrapper, url: *const c_char, network: uint8_t) -> Err {
    CStr::from_ptr(url).to_str().map_or(Err::BadArgument, |url| {
        wrapper.as_mut().map_or(Err::NullArgument, |info_wrapper| {
            let network = if network == 0 { DIDNetwork::Mainnet } else { DIDNetwork::Devnet };
            run_async(create_identity(url, network.clone().into())).map_or(Err::OperationFailed, |(did, keypair, _)| {
                let info = DIDInfo::new(&did, "streams-1", url, network);
                *info_wrapper = safe_into_mut_ptr(DIDInfoWrapper::new(info, keypair.into()));
                Err::Ok
            })
        })
    })
}


#[no_mangle]
pub unsafe extern "C" fn drop_info_wrapper(wrapper: *const DIDInfoWrapper) {
    safe_drop_ptr(wrapper)
}

#[no_mangle]
pub unsafe extern "C" fn drop_info(info: *const DIDInfo) {
    safe_drop_ptr(info)
}

#[no_mangle]
pub unsafe extern "C" fn drop_did_keypair(kp: *const DIDKeypair) {
    safe_drop_ptr(kp)
}
