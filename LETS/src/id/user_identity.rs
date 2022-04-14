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
        DID,
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
            Ed25519,
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
    DIDImpl,
    DIDInfo,
    DIDMethodId,
    DataWrapper,
};
use crate::{
    id::{
        identifier::Identifier,
        psk::{
            Psk,
            PskId,
        },
    },
    message::content::{
        ContentDecrypt,
        ContentEncrypt,
        ContentEncryptSizeOf,
        ContentSign,
        ContentSizeof,
        ContentVerify,
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

#[allow(clippy::large_enum_variant)]
enum Keys {
    Keypair(KeyPairs),
    Psk(Psk),
    #[cfg(feature = "did")]
    DID(DIDImpl),
}

pub(crate) struct UserIdentity<F> {
    id: Identifier,
    keys: Keys,
    // TODO: REMOVE
    // #[cfg(feature = "did")]
    // client: Client,
    // TODO: REMOVE
    _phantom: PhantomData<F>,
}

impl<F> Default for UserIdentity<F> {
    fn default() -> Self {
        // unwrap is fine because we are using default
        let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
        let signing_public_key = signing_private_key.public_key();
        let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
        let key_exchange_public_key = key_exchange_private_key.public_key();

        UserIdentity {
            id: signing_public_key.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: (signing_private_key, signing_public_key),
                key_exchange: (key_exchange_private_key, key_exchange_public_key),
            }),
            // TODO: REMOVE
            // #[cfg(feature = "did")]
            // client: block_on(StreamsClient::default().to_did_client()).unwrap(),
            _phantom: Default::default(),
        }
    }
}

impl<F: PRP> UserIdentity<F> {
    async fn new(seed: &str) -> UserIdentity<F> {
        let signing_private_key = ed25519::SecretKey::generate_with(&mut SpongosRng::<F>::new(seed));
        let signing_public_key = signing_private_key.public_key();
        let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
        let key_exchange_public_key = key_exchange_private_key.public_key();

        UserIdentity {
            id: signing_public_key.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: (signing_private_key, signing_public_key),
                key_exchange: (key_exchange_private_key, key_exchange_public_key),
            }),
            // TODO: REMOVE
            // #[cfg(feature = "did")]
            // client: StreamsClient::default().to_did_client().await.unwrap(),
            _phantom: Default::default(),
        }
    }

    async fn new_from_psk(pskid: PskId, psk: Psk) -> UserIdentity<F> {
        UserIdentity {
            id: pskid.into(),
            keys: Keys::Psk(psk),
            // TODO: REMOVE
            // #[cfg(feature = "did")]
            // client: StreamsClient::default().to_did_client().await.unwrap(),
            _phantom: Default::default(),
        }
    }

    #[cfg(feature = "did")]
    async fn new_with_did_private_key(did_info: DIDInfo) -> Result<UserIdentity<F>> {
        Ok(UserIdentity {
            id: did_info.did()?.into(),
            keys: Keys::DID(DIDImpl::PrivateKey(did_info)),
            // TODO: REMOVE
            // client: StreamsClient::default().to_did_client().await?,
            _phantom: Default::default(),
        })
    }

    // TODO: REMOVE
    // #[cfg(feature = "did")]
    // fn insert_did_client(&mut self, client: Client) {
    //     self.client = client;
    // }
    // TODO: Implement new_from_account implementation

    /// Retrieve the key exchange keypair for encryption while sending packets
    fn ke_kp(&self) -> Result<(x25519::SecretKey, x25519::PublicKey)> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                let secret_key = x25519::SecretKey::from_bytes(keypairs.key_exchange.0.to_bytes());
                let public_key = secret_key.public_key();
                Ok((secret_key, public_key))
            }
            Keys::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
            #[cfg(feature = "did")]
            Keys::DID(did) => match did {
                DIDImpl::PrivateKey(info) => Ok(info.ke_kp()),
                // TODO: Account implementation
            },
        }
    }

    /// Retrieve the signature secret key for user encryption while exporting and importing
    fn sig_sk(&self) -> Result<ed25519::SecretKey> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                let sk_bytes = keypairs.sig.0.to_bytes();
                Ok(ed25519::SecretKey::from_bytes(sk_bytes))
            }
            Keys::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
            #[cfg(feature = "did")]
            Keys::DID(did) => match did {
                DIDImpl::PrivateKey(info) => {
                    let sig_kp = info.sig_kp();
                    Ok(ed25519::SecretKey::from_bytes(sig_kp.0.to_bytes()))
                } // TODO: Account implementation
            },
        }
    }

    /// Sign the prehashed bytes of a message for ownership authentication
    ///
    /// # Arguments
    /// * `data` - Wrapper containing the prehashed bytes of a message
    #[cfg(feature = "did")]
    async fn sign_data(&self, mut data: DataWrapper) -> Result<Signature> {
        match &self.keys {
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let fragment = format!("#{}", info.key_fragment());
                        // Join the DID identifier with the key fragment of the verification method
                        let method = info.did()?.clone().join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(
                            &mut data,
                            method.to_string(),
                            info.keypair().private().as_ref(),
                            SignatureOptions::new(),
                        )?;
                    }
                }
                // Ensure that data signature was set
                match data.into_signature() {
                    Some(sig) => Ok(sig),
                    None => Err(anyhow!("user failed to sign data")),
                }
            }
            _ => Err(anyhow!("user is not a DID user")),
        }
    }

    /// Verify the sending signature of a message sent by another party in the Channel
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `data` - Wrapper containing the prehashed bytes of a message and the sender signature
    #[cfg(feature = "did")]
    async fn verify_data(&self, did: &IotaDID, data: DataWrapper) -> Result<bool> {
        let doc = DIDClient::new().await?.read_document(did).await?;
        match doc.document.verify_data(&data, &VerifierOptions::new()) {
            Ok(_) => Ok(true),
            Err(e) => Ok(false),
        }
    }
}

impl<F> From<(ed25519::SecretKey, ed25519::PublicKey)> for UserIdentity<F> {
    fn from(kp: (ed25519::SecretKey, ed25519::PublicKey)) -> Self {
        let ke_sk = x25519::SecretKey::from(&kp.0);
        let ke_pk = ke_sk.public_key();
        UserIdentity {
            id: Identifier::EdPubKey(kp.1),
            keys: Keys::Keypair(KeyPairs {
                sig: kp,
                key_exchange: (ke_sk, ke_pk),
            }),
            ..Default::default()
        }
    }
}

impl<F> From<Identifier> for UserIdentity<F> {
    fn from(id: Identifier) -> Self {
        UserIdentity {
            id,
            ..Default::default()
        }
    }
}

// Signature Toolset

#[async_trait(?Send)]
impl<'a, F> ContentSizeof<'a> for UserIdentity<F> {
    async fn sizeof<'b>(&'a self, ctx: &'b mut sizeof::Context) -> Result<&'b mut sizeof::Context> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8::new(0))?;
                let mut hash = External::new(NBytes::new([0; 64]));
                ctx.commit()?.squeeze(&hash)?.ed25519(&keys.sig.0, &hash)?;
                return Ok(ctx);
            }
            Keys::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let method_id = decode_b58(info.method_id()?)?;
                        let key_fragment = info.key_fragment().as_bytes().to_vec();
                        ctx.absorb(Uint8::new(1))?
                            .absorb(&NBytes::new(method_id))?
                            .absorb(&Bytes::new(key_fragment))?;
                    } // TODO: Implement Account logic
                }
                // Absorb the size of a did based ed25519 signature
                let bytes = [0_u8; ed25519::SIGNATURE_LENGTH].to_vec();
                ctx.absorb(&Bytes::new(bytes))?;
                return Ok(ctx);
            }
        }
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentSign<F, OS> for UserIdentity<F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign<'c>(&self, ctx: &'c mut wrap::Context<F, OS>) -> Result<&'c mut wrap::Context<F, OS>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8::new(0))?;
                let mut hash = External::new(NBytes::new([0; 64]));
                ctx.commit()?.squeeze(&mut hash)?.ed25519(&keys.sig.0, &hash)?;
                Ok(ctx)
            }
            Keys::Psk(_) => Err(anyhow!("PSKs cannot be used as signature keys")),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let method_id = decode_b58(info.method_id()?)?;
                        let key_fragment = info.key_fragment().as_bytes().to_vec();
                        ctx.absorb(Uint8::new(1))?
                            .absorb(&NBytes::new(method_id))?
                            .absorb(&Bytes::new(key_fragment))?;
                    } // TODO: Implement Account logic
                }
                // Get the hash of the message
                let mut hash = External::new(NBytes::new([0; 64]));
                ctx.commit()?.squeeze(&mut hash)?;
                // Append that hash to the additional context
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(hash.as_ref());
                // Place hash in data wrapper and sign it
                let wrapper = DataWrapper::new(prehashed);

                match self.sign_data(wrapper).await {
                    Ok(signature) => {
                        ctx.absorb(&Bytes::new(decode_b58(signature.value().as_str())?))?;
                        Ok(ctx)
                    }
                    Err(e) => Err(anyhow!(
                        "there was an issue with calculating the signature, cannot wrap message. Cause: {}",
                        e
                    )),
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentVerify<F, IS> for UserIdentity<F>
where
    F: PRP,
    IS: io::IStream,
{
    async fn verify<'c>(&self, ctx: &'c mut unwrap::Context<F, IS>) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8::new(0);
        ctx.absorb(&mut oneof)?;
        match oneof.inner() {
            0 => match &self.id {
                Identifier::EdPubKey(pub_key) => {
                    let mut hash = External::new(NBytes::new([0; 64]));
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(pub_key, &hash)?;
                    Ok(ctx)
                }
                _ => Err(anyhow!(
                    "expected ed25519 public key as identifier option '0', found something else"
                )),
            },
            #[cfg(feature = "did")]
            1 => {
                // Get DID method id
                let mut method_id = DIDMethodId::default();
                let mut fragment_bytes = Bytes::default();
                let mut hash = NBytes::new([0; 64]);
                let mut sig_bytes = Bytes::default();

                ctx.absorb(&mut NBytes::new(&mut method_id))?
                    .absorb(&mut fragment_bytes)?
                    .commit()?
                    .squeeze(&mut External::new(hash))?
                    .absorb(&mut sig_bytes)?;

                let fragment = "#".to_string() + &String::from_utf8(fragment_bytes.into_vec())?;
                let did = method_id.try_to_did()?;
                let did_url = did.join(fragment)?;
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(hash.as_ref());
                let mut signature = Signature::new(JcsEd25519::<DIDEd25519>::NAME, did_url.to_string());
                signature.set_value(SignatureValue::Signature(encode_b58(sig_bytes.as_slice())));

                // Place hash in data wrapper and verify it
                let wrapper = DataWrapper::new(prehashed).with_signature(signature);
                match self.verify_data(did_url.as_ref(), wrapper).await? {
                    true => Ok(ctx),
                    false => Err(anyhow!(
                        "There was an issue with the calculated signature, cannot unwrap message"
                    )),
                }
            }
            o => Err(anyhow!("{} is not a valid identity option", o)),
        }
    }
}

// Encryption Toolset

// TODO: Find a better way to represent this logic without the need for an additional trait
#[async_trait(?Send)]
impl<F> ContentEncryptSizeOf<F> for UserIdentity<F> {
    async fn encrypt_sizeof<'a>(
        &self,
        ctx: &'a mut sizeof::Context,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut sizeof::Context> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), &NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentEncrypt<F, OS> for UserIdentity<F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn encrypt<'a>(
        &self,
        ctx: &'a mut wrap::Context<F, OS>,
        exchange_key: &'a [u8],
        key: &'a [u8],
    ) -> Result<&'a mut wrap::Context<F, OS>> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), &NBytes::new(key)),
                Err(e) => Err(anyhow!("Invalid x25519 key: {}", e)),
            },
        }
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentDecrypt<F, IS> for UserIdentity<F>
where
    F: PRP,
    IS: io::IStream,
{
    async fn decrypt<'a>(
        &self,
        ctx: &'a mut unwrap::Context<F, IS>,
        exchange_key: &'a [u8],
        key: &'a mut [u8],
    ) -> Result<&'a mut unwrap::Context<F, IS>> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External::new(&NBytes::new(Psk::try_from(exchange_key)?)))?
                .commit()?
                .mask(&mut NBytes::new(key)),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::SecretKey::from_bytes(slice), &mut NBytes::new(key)),
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
