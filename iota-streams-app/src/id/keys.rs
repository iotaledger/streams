#[cfg(feature = "use-did")]
use super::DataWrapper;

use crate::{
    id::Identifier,
    message::{
        ContentSign,
        ContentSizeof,
        ContentVerify,
    },
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    prng,
    sponge::prp::PRP,
    Result,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
        Commit,
        Ed25519,
        Squeeze,
    },
    io,
    types::{
        External,
        HashSig,
        NBytes,
        U64,
    },
};

#[cfg(feature = "use-did")]
use iota_streams_core::{
    err,
    iota_identity::{
        core::{
            decode_b58,
            encode_b58,
            Timestamp,
            ToJson,
        },
        crypto::{
            Ed25519 as DIDEd25519,
            JcsEd25519,
            KeyPair as DIDKeyPair,
            KeyType,
            Named,
            PrivateKey as DIDPrivateKey,
            PublicKey as DIDPublicKey,
            SetSignature,
            Signature,
            SignatureValue,
            TrySignatureMut,
        },
        did::MethodScope,
        iota::{
            Client,
            IotaDID,
            IotaDocument,
            IotaVerificationMethod,
            Network,
            TangleRef,
        },
    },
    prelude::{
        String,
        ToString,
        Vec,
    },
    wrapped_err,
    Errors::{
        BadOneof,
        DIDInfoRetrievalFailure,
        DIDMissing,
        DIDRetrievalFailure,
        DIDSetFailure,
        DocumentUpdateFailure,
        SignatureFailure,
    },
    WrappedError,
};

#[cfg(feature = "use-did")]
use iota_streams_core_edsig::signature::ed25519::Signer;

#[cfg(feature = "account")]
use iota_streams_core::iota_identity::account::{
    Account,
    Command,
    IdentityId,
};

#[cfg(feature = "use-did")]
use crate::id::{
    DIDSize,
    DID_CORE,
};
#[cfg(feature = "use-did")]
use iota_streams_ddml::{
    command::Absorb,
    types::{
        Bytes,
        Uint8,
    },
};

pub struct KeyPairs {
    pub id: Identifier,
    #[cfg(feature = "use-did")]
    pub did_info: Option<DIDInfo>,
    pub sig_kp: ed25519::Keypair,
    pub ke_kp: (x25519::StaticSecret, x25519::PublicKey),
}

#[cfg(feature = "use-did")]
pub struct DIDInfo {
    pub did: Option<IotaDID>,
    pub key_fragment: String,
    pub did_client: Client,
}

impl KeyPairs {
    /// Creates a new KeyPairs structure from a unique user seed
    ///
    /// # Arguments
    /// * `seed` - Unique seed for Streams User implementation
    pub fn new<F: PRP>(seed: &str) -> Self {
        let nonce = "TANGLEUSERNONCE".as_bytes().to_vec();
        let prng = prng::from_seed::<F>("IOTA Streams Channels user sig keypair", seed);

        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng, nonce));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        KeyPairs {
            id: sig_kp.public.into(),
            #[cfg(feature = "use-did")]
            did_info: None,
            sig_kp,
            ke_kp,
        }
    }

    /// Create a new KeyPairs structure with default values using an Identifier as the foundation
    ///
    /// # Arguments
    /// * `id` - Identifier of the new KeyPairs instance
    pub async fn new_from_id(id: Identifier) -> Result<Self> {
        match &id {
            Identifier::EdPubKey(pk) => {
                // Unknown Private Key
                let mut bytes = vec![0_u8; 32];
                let x_pk = x25519::public_from_ed25519(&pk.0)?;
                // Expand the bytes with the public key bytes
                bytes.extend_from_slice(pk.0.as_bytes());
                // Make the key pairs for the identity
                let sig_kp = ed25519::Keypair::from_bytes(&bytes)?;
                let ke_kp = (x25519::StaticSecret::from([0_u8; 32]), x_pk);

                let kp = {
                    #[cfg(feature = "use-did")]
                    {
                        let mut kp = KeyPairs {
                            id,
                            did_info: None,
                            sig_kp,
                            ke_kp,
                        };
                        kp.make_default_did_info().await?;
                        kp
                    }
                    #[cfg(not(feature = "use-did"))]
                    KeyPairs { id, sig_kp, ke_kp }
                };
                Ok(kp)
            }
            #[cfg(feature = "use-did")]
            Identifier::DID(did) => {
                let mut kp = KeyPairs {
                    id,
                    did_info: None,
                    sig_kp: ed25519::Keypair::from_bytes(&[0_u8; 64])?,
                    ke_kp: (
                        x25519::StaticSecret::from([0_u8; 32]),
                        x25519::PublicKey::from([0_u8; 32]),
                    ),
                };

                kp.make_default_did_info().await?;
                kp.set_did(did_from_bytes(did)?)?;
                Ok(kp)
            }
            _ => Ok(KeyPairs::default()),
        }
    }
}

#[cfg(feature = "use-did")]
/// Constructors for DID based keypairs
impl KeyPairs {
    #[cfg(feature = "account")]
    /// Creates a new KeyPairs structure from an existing Identity (DID) Account
    ///
    /// # Arguments
    /// * `account` - DID Account Structure
    /// * `key_fragment` - Identifier for new verification method within the DID document
    /// * `did_client` - Identity Client for publishing and retrieving DID documents from the tangle
    pub async fn new_from_account(account: Account, key_fragment: String, did_client: Client) -> Result<KeyPairs> {
        // Get the id of the original document from account, and resolve the identity to verify it
        match account.store().index().await?.get(&IdentityId::from(1)) {
            Some(id) => {
                // Retrieve the document from the tangle
                let doc = account.resolve_identity(id).await?;

                // Generate a new key pair to be used by the DID instance
                let did_sig_kp = DIDKeyPair::new_ed25519()?;
                // Generate keys for streams instance
                let sig_kp = sig_kp_from_did_kp(&did_sig_kp);
                let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

                // Create the command and update the DID account
                let command = Command::create_method()
                    .fragment(&key_fragment)
                    .keypair(did_sig_kp)
                    .finish()?;
                account.update_identity(doc.id(), command).await?;
                let did = doc.id();
                let mut prepend = String::from("#");
                prepend.push_str(&key_fragment);
                let did_info = DIDInfo {
                    did: Some(did.clone()),
                    key_fragment: prepend,
                    did_client,
                };

                Ok(Self {
                    id: did.into(),
                    did_info: Some(did_info),
                    sig_kp,
                    ke_kp,
                })
            }
            None => err(DIDRetrievalFailure),
        }
    }

    /// Creates a new KeyPairs structure from an existing Identity (DID)
    ///
    /// # Arguments
    /// * `seed` - Unique seed for Streams User implementation
    /// * `did_client` - Identity Client for publishing and retrieving DID documents from the tangle
    /// * `did` - String representation of the DID identifier
    /// * `key_fragment` - Identifier for new verification method within the DID document
    /// * `keypair` - DID authentication keypair to verify ownership and update document
    pub async fn new_from_did<F: PRP>(
        seed: &str,
        did_client: Client,
        did: String,
        key_fragment: String,
        keypair: &DIDKeyPair,
    ) -> Result<KeyPairs> {
        // Generate the base layer keypair
        let mut kp = KeyPairs::new::<F>(seed);
        // Create the DID keypair from the generated keypair
        let new_key = did_kp_from_sig_kp(&kp.sig_kp);
        // Retrieve the DID document from the tangle
        let did = IotaDID::parse(did)?;
        let mut doc = did_client.read_document(&did).await?;
        let message_id = doc.message_id().clone();

        // Create a new verification method for the DID document
        let method = IotaVerificationMethod::from_did(did, &new_key, key_fragment.as_str())?;
        assert!(doc.insert_method(MethodScope::VerificationMethod, method));

        // Update the document and sign it with the DID authentication keypair
        doc.set_previous_message_id(message_id);
        doc.set_updated(Timestamp::now_utc());
        doc.sign(keypair.private())?;
        // Publish the updated document to the tangle
        did_client.publish_document(&doc).await?;

        // Prepare a DIDInfo Wrapper and be stored inside the KeyPairs structure
        let mut prepend = String::from("#");
        prepend.push_str(&key_fragment);
        let did_info = DIDInfo {
            did: Some(doc.id().clone()),
            key_fragment: prepend,
            did_client,
        };

        // Update the KeyPairs structure Id and DIDInfo Wrapper
        kp.id = doc.id().into();
        kp.did_info = Some(did_info);

        Ok(kp)
    }

    /// Creates a new KeyPairs structure from an existing DIDInfo wrapper. Used for recovery
    ///
    /// # Arguments
    /// * `seed` - Unique seed for Streams User implementation
    /// * `info` - DID Information wrapper, containing the relevant details and client for DID's
    pub async fn new_from_info<F: PRP>(seed: &str, mut info: DIDInfo) -> Result<KeyPairs> {
        if let Some(did) = &info.did {
            match info.did_client.read_document(did).await {
                Ok(doc) => {
                    let mut kp = KeyPairs::new::<F>(seed);

                    let mut prepend = String::from("#");
                    prepend.push_str(&info.key_fragment);
                    info.key_fragment = prepend;

                    kp.id = doc.id().into();
                    kp.did_info = Some(info);

                    Ok(kp)
                }
                Err(_) => err(DIDRetrievalFailure),
            }
        } else {
            err(DIDMissing)
        }
    }

    // TODO: This currently defaults to mainnet with chrysalis-nodes, we need to figure out a reasonable way to go about
    // making this accessible from the user api
    pub async fn make_default_did_info(&mut self) -> Result<()> {
        let did_client = Client::builder()
            .network(Network::Mainnet)
            .primary_node("https://chrysalis-nodes.iota.org", None, None)?
            .build()
            .await?;
        let info = DIDInfo {
            did: None,
            key_fragment: "".to_string(),
            did_client,
        };
        self.did_info = Some(info);
        Ok(())
    }
}

impl From<ed25519::Keypair> for KeyPairs {
    fn from(sig_kp: ed25519::Keypair) -> Self {
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);
        KeyPairs {
            id: sig_kp.public.into(),
            #[cfg(feature = "use-did")]
            did_info: None,
            sig_kp,
            ke_kp,
        }
    }
}

impl Default for KeyPairs {
    fn default() -> Self {
        let sig_kp = ed25519::Keypair {
            secret: ed25519::SecretKey::from_bytes(&[0; ed25519::SECRET_KEY_LENGTH]).unwrap(),
            public: ed25519::PublicKey::default(),
        };
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);
        KeyPairs {
            id: sig_kp.public.into(),
            #[cfg(feature = "use-did")]
            did_info: None,
            sig_kp,
            ke_kp,
        }
    }
}

#[cfg(feature = "use-did")]
impl KeyPairs {
    /// Sign the prehashed bytes of a message for ownership authentication
    ///
    /// # Arguments
    /// * `data` - Wrapper containing the prehashed bytes of a message
    async fn sign_data(&self, data: &mut DataWrapper) -> Result<Signature> {
        match self.did_info.as_ref() {
            Some(info) => {
                match info.did.as_ref() {
                    Some(did) => {
                        // Join the DID identifier with the key fragment of the verification method
                        let method = did.join(&info.key_fragment)?;
                        // Create and set the signature placeholder for the data wrapper
                        data.set_signature(Signature::new(JcsEd25519::<DIDEd25519>::NAME, method.as_str()));

                        // Sign the JCS representation of the data wrapper and set it
                        let signature = self.sig_kp.sign(&data.to_jcs()?);
                        let write = data.try_signature_mut()?;
                        write.set_value(SignatureValue::Signature(encode_b58(&signature.to_bytes())));
                        match &data.signature {
                            Some(sig) => Ok(sig.clone()),
                            None => err(SignatureFailure),
                        }
                    }
                    None => err(SignatureFailure),
                }
            }
            None => err(SignatureFailure),
        }
    }

    /// Verify the sending signature of a message sent by another party in the Channel
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `data` - Wrapper containing the prehashed bytes of a message and the sender signature
    async fn verify_data(&self, did: &IotaDID, data: DataWrapper) -> Result<bool> {
        match self.did_info.as_ref() {
            Some(info) => {
                let doc = info.did_client.read_document(did).await?;
                match doc.verify_data(&data) {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        println!("Verification Error: {:?}", e);
                        Ok(false)
                    }
                }
            }
            None => err(SignatureFailure),
        }
    }

    /// Set the DID within a KeyPairs Structure
    ///
    /// # Arguments
    /// * `did` - DID identifier
    fn set_did(&mut self, did: IotaDID) -> Result<()> {
        match self.did_info.as_mut() {
            Some(info) => {
                info.did = Some(did);
                Ok(())
            }
            None => err(DIDSetFailure)?,
        }
    }
}

#[cfg(feature = "use-did")]
pub fn sig_kp_from_did_kp(kp: &DIDKeyPair) -> ed25519::Keypair {
    let mut key_bytes = Vec::from(kp.private().as_ref());
    key_bytes.extend(kp.public().as_ref());
    ed25519::Keypair::from_bytes(&key_bytes).unwrap()
}

#[cfg(feature = "use-did")]
pub fn did_kp_from_sig_kp(kp: &ed25519::Keypair) -> DIDKeyPair {
    DIDKeyPair::from((
        KeyType::Ed25519,
        DIDPublicKey::from(kp.public.to_bytes().to_vec()),
        DIDPrivateKey::from(kp.secret.to_bytes().to_vec()),
    ))
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for KeyPairs {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        #[cfg(feature = "use-did")]
        {
            if let Some(info) = self.did_info.as_ref() {
                if let Some(did) = info.did.as_ref() {
                    ctx.absorb(Uint8(1))?;
                    ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                    ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;
                    // Absorb the size of a did based ed25519 signature
                    let bytes = [0_u8; ed25519::SIGNATURE_LENGTH].to_vec();
                    ctx.absorb(&Bytes(bytes))?;
                    return Ok(ctx);
                }
            }
            ctx.absorb(Uint8(0))?;
            ctx.ed25519(&self.sig_kp, HashSig)?;
            Ok(ctx)
        }

        #[cfg(not(feature = "use-did"))]
        {
            ctx.ed25519(&self.sig_kp, HashSig)?;
            Ok(ctx)
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::OStream> ContentSign<F, OS> for KeyPairs {
    async fn sign<'c>(&self, ctx: &'c mut wrap::Context<F, OS>) -> Result<&'c mut wrap::Context<F, OS>> {
        #[cfg(feature = "use-did")]
        {
            if let Some(info) = self.did_info.as_ref() {
                if let Some(did) = info.did.as_ref() {
                    ctx.absorb(Uint8(1))?;
                    // Absorb did method and fragment
                    ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                    ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;

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
            ctx.absorb(Uint8(0))?;
            let mut hash = External(NBytes::<U64>::default());
            ctx.commit()?.squeeze(&mut hash)?.ed25519(&self.sig_kp, &hash)?;
            Ok(ctx)
        }

        #[cfg(not(feature = "use-did"))]
        {
            let mut hash = External(NBytes::<U64>::default());
            ctx.commit()?.squeeze(&mut hash)?.ed25519(&self.sig_kp, &hash)?;
            Ok(ctx)
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, IS: io::IStream> ContentVerify<'_, F, IS> for KeyPairs {
    async fn verify<'c>(&self, ctx: &'c mut unwrap::Context<F, IS>) -> Result<&'c mut unwrap::Context<F, IS>> {
        #[cfg(feature = "use-did")]
        {
            let mut oneof = Uint8(0);
            ctx.absorb(&mut oneof)?;
            match oneof.0 {
                0 => {
                    let mut hash = External(NBytes::<U64>::default());
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(&self.sig_kp.public, &hash)?;
                    Ok(ctx)
                }
                1 => {
                    match self.did_info.as_ref() {
                        Some(_info) => {
                            let mut bytes = NBytes::<DIDSize>::default();
                            ctx.absorb(&mut bytes)?;
                            let mut did = did_from_bytes(&bytes.0)?;

                            let mut bytes = Bytes(Vec::new());
                            ctx.absorb(&mut bytes)?;
                            let fragment = String::from_utf8(bytes.0)?;

                            // Join fragment to did
                            did = did.join(fragment)?;

                            // Get te hash of the message
                            let mut hash = External(NBytes::<U64>::default());
                            ctx.commit()?.squeeze(&mut hash)?;
                            // Append that hash to the additional context
                            let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                            prehashed.extend_from_slice(&(hash.0).0);

                            let mut sig_bytes = Bytes(Vec::new());
                            ctx.absorb(&mut sig_bytes)?;
                            let mut signature = Signature::new(JcsEd25519::<DIDEd25519>::NAME, did.as_str());
                            signature.set_value(SignatureValue::Signature(encode_b58(&sig_bytes.0)));

                            // Place hash in data wrapper and sign it
                            let wrapper = DataWrapper {
                                data: prehashed,
                                signature: Some(signature),
                            };
                            match self.verify_data(&did, wrapper).await? {
                                true => Ok(ctx),
                                false => err(SignatureFailure),
                            }
                        }
                        None => err(DIDInfoRetrievalFailure)?,
                    }
                }
                _ => err(BadOneof)?,
            }
        }

        #[cfg(not(feature = "use-did"))]
        {
            let mut hash = External(NBytes::<U64>::default());
            ctx.commit()?.squeeze(&mut hash)?.ed25519(&self.sig_kp.public, &hash)?;
            Ok(ctx)
        }
    }
}

#[cfg(feature = "use-did")]
fn did_from_bytes(bytes: &[u8]) -> Result<IotaDID> {
    let mut did = DID_CORE.to_string();
    did.push_str(&encode_b58(bytes));
    Ok(IotaDID::parse(did)?)
}

#[cfg(feature = "use-did")]
/// Create a new Identity with default settings
pub async fn create_identity(url: &str, network: Network) -> Result<(String, DIDKeyPair, Client)> {
    match Client::builder()
        .network(network)
        .primary_node(url, None, None)?
        .build()
        .await
    {
        Ok(client) => {
            // Create Keypair to act as base of identity
            let keypair = DIDKeyPair::new_ed25519()?;
            // Generate original DID document
            let mut document = IotaDocument::new(&keypair)?;
            // Sign document and publish to the tangle
            document.sign(keypair.private())?;
            let receipt = client.publish_document(&document).await?;
            println!("Document published: {}", receipt.message_id());

            // Return the DID string, keypair and client instance
            Ok((document.id().to_string(), keypair, client))
        }
        Err(e) => Err(wrapped_err(DocumentUpdateFailure, WrappedError(e))),
    }
}
