// Rust
use alloc::{
    boxed::Box,
    string::{
        String,
        ToString,
    },
    vec::Vec,
};
use core::{
    convert::TryFrom,
    marker::PhantomData,
};

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;
// TODO: REMOVE
// use generic_array::{
//     typenum::U64,
//     ArrayLength,
//     GenericArray,
// };

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
#[cfg(feature = "did")]
use identity::{
    core::{
        decode_b58,
        encode_b58,
    },
    crypto::{
        Ed25519 as DIDEd25519,
        JcsEd25519,
        Named,
        Signature,
        SignatureOptions,
        SignatureValue,
        Signer,
    },
    did::{
        verifiable::VerifierOptions,
        DID as IdentityDID,
    },
    iota::{
        Client as DIDClient,
        IotaDID,
    },
};

// IOTA-Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Ed25519 as Ed25519Command,
            Mask,
            Squeeze,
            X25519,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Uint8,
        },
    },
    SpongosRng,
    PRP,
};

// Local
#[cfg(feature = "did")]
use crate::id::did::{
    DIDInfo,
    DIDMethodId,
    DataWrapper,
    DID,
};
use crate::{
    id::{
        identifier::Identifier,
        psk::{
            Psk,
            PskId,
        },
    },
    message::{
        content::{
            ContentDecrypt,
            ContentEncrypt,
            ContentEncryptSizeOf,
            ContentSign,
            ContentSizeof,
            ContentVerify,
        },
        ContentSignSizeof,
    },
};

// TODO: REMOVE
// use iota_streams_core::{
//     async_trait,
//     err,
//     prelude::Box,
//     prng,
//     psk::{
//         Psk,
//         PskId,
//         PskSize,
//     },
//     sponge::prp::PRP,
//     wrapped_err,
//     Errors::{
//         BadIdentifier,
//         BadOneof,
//         NoSignatureKeyPair,
//     },
//     Result,
//     WrappedError,
// };
// #[cfg(feature = "did")]
// use crate::{
//     id::{
//         DIDImpl,
//         DIDInfo,
//         DIDSize,
//         DataWrapper,
//         DID_CORE,
//     },
//     transport::tangle::client::Client as StreamsClient,
// };

// #[cfg(feature = "did")]
// use futures::executor::block_on;
// #[cfg(feature = "did")]
// use identity::{
//     core::{
//         decode_b58,
//         encode_b58,
//     },
//     crypto::{
//         Ed25519 as DIDEd25519,
//         JcsEd25519,
//         Named,
//         Signature,
//         SignatureOptions,
//         SignatureValue,
//         Signer,
//     },
//     did::{
//         verifiable::VerifierOptions,
//         DID,
//     },
//     iota::{
//         Client,
//         IotaDID,
//     },
// };

// TODO: REMOVE
// #[cfg(feature = "did")]
// use iota_streams_core::{
//     prelude::{
//         String,
//         ToString,
//         Vec,
//     },
//     Errors::{
//         NotDIDUser,
//         SignatureFailure,
//         SignatureMismatch,
//     },
// };

// #[cfg(feature = "did")]
// use iota_streams_ddml::types::Bytes;

struct KeyPairs {
    sig: (ed25519::SecretKey, ed25519::PublicKey),
    key_exchange: (x25519::SecretKey, x25519::PublicKey),
}

pub struct Ed25519(ed25519::SecretKey);

impl Ed25519 {
    fn new(secret: ed25519::SecretKey) -> Self {
        Self(secret)
    }

    fn from_seed<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP,
    {
        Self(ed25519::SecretKey::generate_with(&mut SpongosRng::<F>::new(seed)))
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Identity {
    Ed25519(Ed25519),
    Psk(Psk),
    #[cfg(feature = "did")]
    DID(DID),
}

// TODO: REMOVE
// pub struct Identity {
//     // TODO: REMOVE AND MOVE KEYS TO IDENTITY
//     id: Identifier,
//     keys: Self,
//     // TODO: REMOVE
//     // #[cfg(feature = "did")]
//     // client: Client,
//     // TODO: REMOVE
//     _phantom: PhantomData<()>,
// }

impl Default for Identity {
    fn default() -> Self {
        // unwrap is fine because we are using default
        let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
        let signing_public_key = signing_private_key.public_key();
        let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
        let key_exchange_public_key = key_exchange_private_key.public_key();

        Self::Ed25519(Ed25519(signing_private_key))
        // TODO: REMOVE
        // Identity {
        //     id: signing_public_key.into(),
        //     keys: Self::Ed25519(KeyPairs {
        //         sig: (signing_private_key, signing_public_key),
        //         key_exchange: (key_exchange_private_key, key_exchange_public_key),
        //     }),
        //     // TODO: REMOVE
        //     // #[cfg(feature = "did")]
        //     // client: block_on(StreamsClient::default().to_did_client()).unwrap(),
        //     _phantom: Default::default(),
        // }
    }
}

impl Identity {
    // TODO: MOVE TO KEYS
    // async fn new(seed: &str) -> Identity {
    //     let signing_private_key = ed25519::SecretKey::generate_with(&mut SpongosRng::::new(seed));
    //     let signing_public_key = signing_private_key.public_key();
    //     let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
    //     let key_exchange_public_key = key_exchange_private_key.public_key();

    //     Identity {
    //         id: signing_public_key.into(),
    //         keys: Self::Ed25519(KeyPairs {
    //             sig: (signing_private_key, signing_public_key),
    //             key_exchange: (key_exchange_private_key, key_exchange_public_key),
    //         }),
    //         // TODO: REMOVE
    //         // #[cfg(feature = "did")]
    //         // client: StreamsClient::default().to_did_client().await.unwrap(),
    //         _phantom: Default::default(),
    //     }
    // }

    // async fn ed25519(ed25519: Ed25519) -> Self {
    //     Self::Ed25519(ed25519)
    // }

    // async fn psk(psk: Psk) -> Self {
    //     Self::Psk(psk)

    // Identity {
    //     id: pskid.into(),
    //     keys: Self::Psk(psk),
    //     // TODO: REMOVE
    //     // #[cfg(feature = "did")]
    //     // client: StreamsClient::default().to_did_client().await.unwrap(),
    //     _phantom: Default::default(),
    // }
    // }

    // #[cfg(feature = "did")]
    // async fn did(did: DIDImpl) -> Self {
    //         Self::DID(did)
    // }

    // TODO: REMOVE
    // #[cfg(feature = "did")]
    // fn insert_did_client(&mut self, client: Client) {
    //     self.client = client;
    // }
    // TODO: Implement new_from_account implementation

    // TODO: REMOVE
    // /// Retrieve the key exchange keypair
    // fn ke_kp(&self) -> Option<(x25519::SecretKey, x25519::PublicKey)> {
    //     match self {
    //         Self::Ed25519(Ed25519(ed_secret)) => {
    //             let x_secret = ed_secret.into();
    //             Some((x_secret, x_secret.public_key()))
    //         }
    //         Self::Psk(_) => None,
    //         #[cfg(feature = "did")]
    //         Self::DID(did) => match did {
    //             DIDImpl::PrivateKey(info) => Some(info.ke_kp()),
    //             // TODO: Account implementation
    //         },
    //     }
    // }

    // /// Retrieve the signature secret key for user encryption while exporting and importing
    // fn sig_sk(&self) -> Option<ed25519::SecretKey> {
    //     // TODO: REMOVE METHOD
    //     match &self.keys {
    //         Self::Ed25519(keypairs) => {
    //             let sk_bytes = keypairs.sig.0.to_bytes();
    //             Ok(ed25519::SecretKey::from_bytes(sk_bytes))
    //         }
    //         Self::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
    //         #[cfg(feature = "did")]
    //         Self::DID(did) => match did {
    //             DIDImpl::PrivateKey(info) => {
    //                 let sig_kp = info.sig_kp();
    //                 Ok(ed25519::SecretKey::from_bytes(sig_kp.0.to_bytes()))
    //             } // TODO: Account implementation
    //         },
    //     }
    // }

    pub fn to_identifier(&self) -> Identifier {
        match self {
            Self::Ed25519(Ed25519(secret)) => secret.public_key().into(),
            Self::Psk(psk) => psk.into(),
            Self::DID(did) => did.info().did().into(),
        }
    }

    // TODO: REMOVE
    // /// Sign the prehashed bytes of a message for ownership authentication
    // ///
    // /// # Arguments
    // /// * `data` - Wrapper containing the prehashed bytes of a message
    // #[cfg(feature = "did")]
    // async fn sign_data(&self, mut data: DataWrapper) -> Result<Signature> {
    //     match self {
    //         Self::DID(did_impl) => {
    //             match did_impl {
    //                 DID::PrivateKey(info) => {
    //                     let fragment = format!("#{}", info.key_fragment());
    //                     // Join the DID identifier with the key fragment of the verification method
    //                     let method = info.did().clone().join(&fragment)?;
    //                     JcsEd25519::<DIDEd25519>::create_signature(
    //                         &mut data,
    //                         method.to_string(),
    //                         info.keypair().private().as_ref(),
    //                         SignatureOptions::new(),
    //                     )?;
    //                 }
    //             }
    //             // Ensure that data signature was set
    //             match data.into_signature() {
    //                 Some(sig) => Ok(sig),
    //                 None => Err(anyhow!("user failed to sign data")),
    //             }
    //         }
    //         _ => Err(anyhow!("user is not a DID user")),
    //     }
    // }
}

impl From<Identity> for Identifier {
    fn from(identity: Identity) -> Self {
        identity.to_identifier()
    }
}
// TODO: REMOVE
// impl From<(ed25519::SecretKey, ed25519::PublicKey)> for Identity {
//     fn from(kp: (ed25519::SecretKey, ed25519::PublicKey)) -> Self {
//         let ke_sk = x25519::SecretKey::from(&kp.0);
//         let ke_pk = ke_sk.public_key();
//         Identity {
//             id: Identifier::EdPubKey(kp.1),
//             keys: Self::Ed25519(KeyPairs {
//                 sig: kp,
//                 key_exchange: (ke_sk, ke_pk),
//             }),
//             ..Default::default()
//         }
//     }
// }

// TODO: REMOVE
// impl From<Identifier> for Identity {
//     fn from(id: Identifier) -> Self {
//         Identity {
//             id,
//             ..Default::default()
//         }
//     }
// }

// Signature Toolset

// #[async_trait(?Send)]
// impl<'a> ContentSizeof<'a> for Identity {
//     async fn sizeof<'b>(&'a self, ctx: &'b mut sizeof::Context) -> Result<&'b mut sizeof::Context> {
//         match self{
//             Self::Ed25519(Ed25519(secret)) => {
//                 ctx.absorb(Uint8::new(0))?;
//                 let mut hash = External::new(NBytes::new([0; 64]));
//                 ctx.commit()?.squeeze(&hash)?.ed25519(secret, &hash)?;
//                 return Ok(ctx);
//             }
//             Self::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
//             #[cfg(feature = "did")]
//             Self::DID(did_impl) => {
//                 match did_impl {
//                     DID::PrivateKey(info) => {
//                         let method_id = decode_b58(info.method_id())?;
//                         let key_fragment = info.key_fragment().as_bytes().to_vec();
//                         ctx.absorb(Uint8::new(1))?
//                             .absorb(&NBytes::new(method_id))?
//                             .absorb(&Bytes::new(key_fragment))?;
//                     } // TODO: Implement Account logic
//                 }
//                 // Absorb the size of a did based ed25519 signature
//                 let bytes = [0_u8; ed25519::SIGNATURE_LENGTH].to_vec();
//                 ctx.absorb(&Bytes::new(bytes))?;
//                 return Ok(ctx);
//             }
//         }
//     }
// }

#[async_trait(?Send)]
impl ContentSignSizeof<Identity> for sizeof::Context {
    async fn sign_sizeof(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(Ed25519(secret)) => {
                let hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(&hash)?
                    .ed25519(secret, &hash)?;
                Ok(self)
            }

            Identity::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => match did_impl {
                DID::PrivateKey(info) => {
                    let hash = [0; 64];
                    let key_fragment = info.key_fragment().as_bytes().to_vec();
                    let signature = [0; 64];
                    self.absorb(Uint8::new(1))?
                        .absorb(&Bytes::new(key_fragment))?
                        .commit()?
                        .squeeze(External::new(&NBytes::new(&hash)))?
                        .absorb(&NBytes::new(signature))
                }
            },
        }
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentSign<Identity> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign(&mut self, signer: &Identity) -> Result<&mut Self> {
        match signer {
            Identity::Ed25519(Ed25519(secret)) => {
                let mut hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(&mut hash)?
                    .ed25519(secret, &hash)?;
                Ok(self)
            }

            Identity::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),

            #[cfg(feature = "did")]
            Identity::DID(did_impl) => {
                match did_impl {
                    DID::PrivateKey(info) => {
                        let mut hash = [0; 64];
                        let key_fragment = info.key_fragment().as_bytes().to_vec();
                        self.absorb(Uint8::new(1))?
                            .absorb(&Bytes::new(key_fragment))?
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?;

                        let mut data = DataWrapper::new(&hash);
                        let fragment = format!("#{}", info.key_fragment());
                        // Join the DID identifier with the key fragment of the verification method
                        let method = info.did().clone().join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(
                            &mut data,
                            method.to_string(),
                            info.keypair().private().as_ref(),
                            SignatureOptions::new(),
                        )?;
                        let signature = decode_b58(
                            &data
                                .into_signature()
                                .ok_or_else(|| {
                                    anyhow!("there was an issue with calculating the signature, cannot wrap message")
                                })?
                                .value()
                                .as_str(),
                        )?;
                        self.absorb(&NBytes::new(signature))
                        // match signer.sign_data(wrapper).await {
                        //     Ok(signature) => {
                        //         self.absorb(&Bytes::new(decode_b58(signature.value().as_str())?))?;
                        //         Ok(self)
                        //     }
                        //     Err(e) => Err(anyhow!(
                        //         e
                        //     )),
                        // }
                    } // TODO: Implement Account logic
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentDecrypt<Identity> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    async fn decrypt(&mut self, recipient: &Identity, exchange_key: &[u8], key: &mut [u8]) -> Result<&mut Self> {
        match recipient {
            Identity::Psk(_) => self
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&mut NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introduction)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => self.x25519(&x25519::SecretKey::from_bytes(slice), &mut NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}

// TODO: REMOVE
// #[cfg(feature = "did")]
// fn did_from_bytes(bytes: &[u8]) -> Result<IotaDID> {
//     let mut did = DID_CORE.to_string();
//     did.push_str(&encode_b58(bytes));
//     Ok(IotaDID::parse(did)?)
// }
