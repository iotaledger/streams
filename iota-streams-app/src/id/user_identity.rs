use crate::{
    permission::Permission,
    id::Identifier,
    message::{
        ContentSign,
        ContentSizeof,
        ContentVerify,
    },
};
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use iota_streams_core::{
    async_trait,
    err,
    prelude::Box,
    prng,
    psk::{
        Psk,
        PskId,
        PskSize,
    },
    sponge::prp::PRP,
    wrapped_err,
    Errors::{
        BadIdentifier,
        BadOneof,
        NoSignatureKeyPair,
    },
    Result,
    WrappedError,
};
use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
        Absorb,
        Commit,
        Ed25519,
        Squeeze,
    },
    io,
    types::{
        External,
        HashSig,
        NBytes,
        Uint8,
        U64,
    },
};
use std::{
    convert::TryFrom,
    marker::PhantomData,
};

use crate::message::{
    ContentDecrypt,
    ContentEncrypt,
    ContentEncryptSizeOf,
};
#[cfg(feature = "did")]
use crate::{
    id::{
        DIDImpl,
        DIDInfo,
        DIDSize,
        DataWrapper,
        DID_CORE,
    },
    transport::tangle::client::Client as StreamsClient,
};
#[cfg(feature = "did")]
use futures::executor::block_on;
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
        Client,
        IotaDID,
    },
};
#[cfg(feature = "did")]
use iota_streams_core::{
    prelude::{
        String,
        ToString,
        Vec,
    },
    Errors::{
        NotDIDUser,
        SignatureFailure,
        SignatureMismatch,
    },
};
#[cfg(feature = "did")]
use iota_streams_ddml::types::Bytes;
use iota_streams_ddml::{
    command::{
        Mask,
        X25519,
    },
    types::ArrayLength,
};

pub struct KeyPairs {
    sig: (ed25519::SecretKey, ed25519::PublicKey),
    key_exchange: (x25519::SecretKey, x25519::PublicKey),
}

#[allow(clippy::large_enum_variant)]
pub enum Keys {
    Keypair(KeyPairs),
    Psk(Psk),
    #[cfg(feature = "did")]
    DID(DIDImpl),
}

pub struct UserIdentity<F> {
    pub id: Identifier,
    keys: Keys,
    #[cfg(feature = "did")]
    client: Client,
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
            #[cfg(feature = "did")]
            client: block_on(StreamsClient::default().to_did_client()).unwrap(),
            _phantom: Default::default(),
        }
    }
}

impl<F: PRP> UserIdentity<F> {
    pub async fn new(seed: &str) -> UserIdentity<F> {
        let nonce = "TANGLEUSERNONCE".as_bytes().to_vec();
        let prng = prng::from_seed::<F>("IOTA Streams Channels user sig keypair", seed);

        let signing_private_key = ed25519::SecretKey::generate_with(&mut prng::Rng::new(prng, nonce));
        let signing_public_key = signing_private_key.public_key();
        let key_exchange_private_key = x25519::SecretKey::from(&signing_private_key);
        let key_exchange_public_key = key_exchange_private_key.public_key();

        UserIdentity {
            id: signing_public_key.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: (signing_private_key, signing_public_key),
                key_exchange: (key_exchange_private_key, key_exchange_public_key),
            }),
            #[cfg(feature = "did")]
            client: StreamsClient::default().to_did_client().await.unwrap(),
            _phantom: Default::default(),
        }
    }

    pub async fn new_from_psk(pskid: PskId, psk: Psk) -> UserIdentity<F> {
        UserIdentity {
            id: pskid.into(),
            keys: Keys::Psk(psk),
            #[cfg(feature = "did")]
            client: StreamsClient::default().to_did_client().await.unwrap(),
            _phantom: Default::default(),
        }
    }

    #[cfg(feature = "did")]
    pub async fn new_with_did_private_key(did_info: DIDInfo) -> Result<UserIdentity<F>> {
        let did = did_info.did()?;
        Ok(UserIdentity {
            id: (&did).into(),
            keys: Keys::DID(DIDImpl::PrivateKey(did_info)),
            client: StreamsClient::default().to_did_client().await?,
            _phantom: Default::default(),
        })
    }

    #[cfg(feature = "did")]
    pub fn insert_did_client(&mut self, client: Client) {
        self.client = client;
    }
    // TODO: Implement new_from_account implementation

    /// Retrieve the key exchange keypair for encryption while sending packets
    pub fn ke_kp(&self) -> Result<(x25519::SecretKey, x25519::PublicKey)> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                let secret_key = x25519::SecretKey::from_bytes(keypairs.key_exchange.0.to_bytes());
                let public_key = secret_key.public_key();
                Ok((secret_key, public_key))
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did) => match did {
                DIDImpl::PrivateKey(info) => Ok(info.ke_kp()),
                // TODO: Account implementation
            },
        }
    }

    /// Retrieve the signature secret key for user encryption while exporting and importing
    pub fn sig_sk(&self) -> Result<ed25519::SecretKey> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                let sk_bytes = keypairs.sig.0.to_bytes();
                Ok(ed25519::SecretKey::from_bytes(sk_bytes))
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
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
    async fn sign_data(&self, data: &mut DataWrapper) -> Result<Signature> {
        match &self.keys {
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let did = info.did()?;
                        let fragment = "#".to_string() + &info.key_fragment;
                        // Join the DID identifier with the key fragment of the verification method
                        let method = did.join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(
                            data,
                            method.to_string(),
                            info.did_keypair.private().as_ref(),
                            SignatureOptions::new(),
                        )?;
                    }
                }
                // Ensure that data signature was set
                match &data.signature {
                    Some(sig) => Ok(sig.clone()),
                    None => err(SignatureFailure),
                }
            }
            _ => err(NotDIDUser),
        }
    }

    /// Verify the sending signature of a message sent by another party in the Channel
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `data` - Wrapper containing the prehashed bytes of a message and the sender signature
    #[cfg(feature = "did")]
    async fn verify_data(&self, did: &IotaDID, data: DataWrapper) -> Result<bool> {
        let doc = self.client.read_document(did).await?;
        match doc.document.verify_data(&data, &VerifierOptions::new()) {
            Ok(_) => Ok(true),
            Err(e) => {
                println!("Verification Error: {:?}", e);
                Ok(false)
            }
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

impl<F> From<Permission> for UserIdentity<F> {
    fn from(permission: Permission) -> Self {
        UserIdentity {
            // TODO FIX CLONE
            id: permission.identifier().clone(),
            ..Default::default()
        }
    }
}

// Signature Toolset

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for UserIdentity<F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                ctx.ed25519(&keys.sig.0, HashSig)?;
                return Ok(ctx);
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let did = info.did()?;
                        ctx.absorb(Uint8(1))?;
                        ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                        ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;
                    } // TODO: Implement Account logic
                }
                // Absorb the size of a did based ed25519 signature
                let bytes = [0_u8; ed25519::SIGNATURE_LENGTH].to_vec();
                ctx.absorb(&Bytes(bytes))?;
                return Ok(ctx);
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::OStream> ContentSign<F, OS> for UserIdentity<F> {
    async fn sign<'c>(&self, ctx: &'c mut wrap::Context<F, OS>) -> Result<&'c mut wrap::Context<F, OS>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?.ed25519(&keys.sig.0, &hash)?;
                Ok(ctx)
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let did = info.did()?;
                        ctx.absorb(Uint8(1))?;
                        ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                        ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;
                    } // TODO: Implement Account logic
                }
                // Get the hash of the message
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?;
                // Append that hash to the additional context
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(&(hash.0).0);
                // Place hash in data wrapper and sign it
                let mut wrapper = DataWrapper {
                    data: prehashed,
                    signature: None,
                };

                match self.sign_data(&mut wrapper).await {
                    Ok(signature) => {
                        ctx.absorb(&Bytes(decode_b58(signature.value().as_str())?))?;
                        return Ok(ctx);
                    }
                    Err(e) => return Err(wrapped_err!(SignatureFailure, WrappedError(e))),
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, IS: io::IStream> ContentVerify<'_, F, IS> for UserIdentity<F> {
    async fn verify<'c>(&self, ctx: &'c mut unwrap::Context<F, IS>) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8(0);
        ctx.absorb(&mut oneof)?;
        match oneof.0 {
            0 => match &self.id {
                Identifier::EdPubKey(pub_key) => {
                    let mut hash = External(NBytes::<U64>::default());
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(pub_key, &hash)?;
                    Ok(ctx)
                }
                _ => err!(BadIdentifier),
            },
            #[cfg(feature = "did")]
            1 => {
                // Get DID method id
                let mut bytes = NBytes::<DIDSize>::default();
                ctx.absorb(&mut bytes)?;
                let did = did_from_bytes(&bytes.0)?;

                // Get key fragment
                let mut bytes = Bytes(Vec::new());
                ctx.absorb(&mut bytes)?;
                let fragment = "#".to_string() + &String::from_utf8(bytes.0)?;

                // Join fragment to did
                let did_url = did.join(fragment)?;
                // Get te hash of the message
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?;
                // Append that hash to the additional context
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(&(hash.0).0);

                let mut sig_bytes = Bytes(Vec::new());
                ctx.absorb(&mut sig_bytes)?;
                let mut signature = Signature::new(JcsEd25519::<DIDEd25519>::NAME, did_url.to_string());
                signature.set_value(SignatureValue::Signature(encode_b58(&sig_bytes.0)));

                // Place hash in data wrapper and verify it
                let wrapper = DataWrapper {
                    data: prehashed,
                    signature: Some(signature),
                };
                match self.verify_data(did_url.as_ref(), wrapper).await? {
                    true => Ok(ctx),
                    false => err(SignatureMismatch),
                }
            }
            _ => err(BadOneof),
        }
    }
}

// Encryption Toolset

// TODO: Find a better way to represent this logic without the need for an additional trait
#[async_trait(?Send)]
impl<F: PRP> ContentEncryptSizeOf<F> for UserIdentity<F> {
    async fn encrypt_sizeof<'c, N: ArrayLength<u8>>(
        &self,
        ctx: &'c mut sizeof::Context<F>,
        exchange_key: &'c [u8],
        key: &'c NBytes<N>,
    ) -> Result<&'c mut sizeof::Context<F>> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External(<&NBytes<PskSize>>::from(exchange_key)))?
                .commit()?
                .mask(key),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), key),
                Err(e) => Err(wrapped_err(BadIdentifier, WrappedError(e))),
            },
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::OStream> ContentEncrypt<F, OS> for UserIdentity<F> {
    async fn encrypt<'c, N: ArrayLength<u8>>(
        &self,
        ctx: &'c mut wrap::Context<F, OS>,
        exchange_key: &'c [u8],
        key: &'c NBytes<N>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External(<&NBytes<PskSize>>::from(exchange_key)))?
                .commit()?
                .mask(key),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::PublicKey::from(slice), key),
                Err(e) => Err(wrapped_err(BadIdentifier, WrappedError(e))),
            },
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::IStream> ContentDecrypt<F, OS> for UserIdentity<F> {
    async fn decrypt<'c, N: ArrayLength<u8>>(
        &self,
        ctx: &'c mut unwrap::Context<F, OS>,
        exchange_key: &'c [u8],
        key: &'c mut NBytes<N>,
    ) -> Result<&'c mut unwrap::Context<F, OS>> {
        match &self.id {
            Identifier::PskId(_) => ctx
                .absorb(External(<&NBytes<PskSize>>::from(exchange_key)))?
                .commit()?
                .mask(key),
            // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey introdution)
            _ => match <[u8; 32]>::try_from(exchange_key) {
                Ok(slice) => ctx.x25519(&x25519::SecretKey::from_bytes(slice), key),
                Err(e) => Err(wrapped_err(BadIdentifier, WrappedError(e))),
            },
        }
    }
}

#[cfg(feature = "did")]
fn did_from_bytes(bytes: &[u8]) -> Result<IotaDID> {
    let mut did = DID_CORE.to_string();
    did.push_str(&encode_b58(bytes));
    Ok(IotaDID::parse(did)?)
}
