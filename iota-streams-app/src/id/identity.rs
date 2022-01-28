use crate::id::Identifier;
use crate::message::{ContentSign, ContentSizeof, ContentVerify};
use core::borrow::Borrow;
use std::marker::PhantomData;
use iota_streams_core::{
    async_trait,
    err,
    Errors::{BadIdentifier, BadOneof, NoSignatureKeyPair, NotAPskUser},
    prelude::Box,
    psk::{Psk, PskId},
    prng,
    Result,
    sponge::prp::PRP,
};
use iota_streams_core_edsig::{
    key_exchange::x25519::{self, keypair_from_ed25519},
    signature::ed25519::{self, Keypair},
};
use iota_streams_ddml::{
    command::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519, Squeeze},
    io,
    types::{External, HashSig, NBytes, Uint8, U64},
};


pub struct KeyPairs {
    sig: ed25519::Keypair,
    key_exchange: (x25519::StaticSecret, x25519::PublicKey),
}

pub enum Keys {
    Keypair(KeyPairs),
    Psk(Psk),
    //TODO: Add DID implementation keys
}

pub struct Identity<F> {
    pub id: Identifier,
    keys: Keys,
    _phantom: PhantomData<F>
}

impl<F> Default for Identity<F> {
    fn default() -> Self {
        //unwrap is fine because we are using default
        let sig_kp = ed25519::Keypair::from_bytes(&[0; 64]).unwrap();
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        Identity {
            id: sig_kp.public.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: sig_kp,
                key_exchange: ke_kp,
            }),
            _phantom: Default::default()
        }
    }
}

impl<F: PRP> Identity<F> {
    pub fn new(seed: &str) -> Identity<F> {
        let nonce = "TANGLEUSERNONCE".as_bytes().to_vec();
        let prng = prng::from_seed::<F>("IOTA Streams Channels user sig keypair", seed);

        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng, nonce));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        Identity {
            id: sig_kp.public.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: sig_kp,
                key_exchange: ke_kp,
            }),
            _phantom: Default::default()
        }
    }

    pub fn new_from_psk(pskid: PskId, psk: Psk) -> Identity<F> {
        Identity {
            id: pskid.into(),
            keys: Keys::Psk(psk),
            _phantom: Default::default()
        }

    }

    pub fn set_id(&mut self, id: &Identifier) {
        self.id = *id
    }

    //TODO: Implement new_from_did and new_from_account implementations
    //TODO: Implement DID based sign and verify

    pub fn get_ke_kp(&self) -> Result<&(x25519::StaticSecret, x25519::PublicKey)> {
        match &self.keys {
            Keys::Keypair(keypairs) => Ok(keypairs.key_exchange.borrow()),
            Keys::Psk(_) => err(NoSignatureKeyPair)
        }
    }

    pub fn get_sig_kp(&self) -> Result<&ed25519::Keypair> {
        match &self.keys {
            Keys::Keypair(keypairs) => Ok(&keypairs.sig),
            Keys::Psk(_) => err(NoSignatureKeyPair)
        }
    }

    pub fn get_psk(&self) -> Result<Psk> {
        match &self.keys {
            Keys::Psk(psk) => Ok(*psk),
            Keys::Keypair(_) => err(NotAPskUser)
        }
    }
}

impl<F> From<ed25519::Keypair> for Identity<F> {
    fn from(kp: Keypair) -> Self {
        let ke_kp = keypair_from_ed25519(&kp);
        Identity {
            id: Identifier::EdPubKey(kp.public.into()),
            keys: Keys::Keypair(KeyPairs {
                sig: kp,
                key_exchange: ke_kp,
            }),
            ..Default::default()
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for Identity<F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                ctx.ed25519(&keys.sig, HashSig)?;
                return Ok(ctx);
            }
            Keys::Psk(_) => err(NoSignatureKeyPair)
            //TODO: Implement DID logic
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::OStream> ContentSign<F, OS> for Identity<F> {
    async fn sign<'c>(&self, ctx: &'c mut wrap::Context<F, OS>) -> Result<&'c mut wrap::Context<F, OS>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?.ed25519(&keys.sig, &hash)?;
                Ok(ctx)
            }
            Keys::Psk(_) => err(NoSignatureKeyPair)
            //TODO: Implement DID logic
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, IS: io::IStream> ContentVerify<'_, F, IS> for Identity<F> {
    async fn verify<'c>(&self, ctx: &'c mut unwrap::Context<F, IS>) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8(0);
        ctx.absorb(&mut oneof)?;
        match oneof.0 {
            0 => match &self.id {
                Identifier::EdPubKey(pub_key_wrap) => {
                    let mut hash = External(NBytes::<U64>::default());
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(&pub_key_wrap.0, &hash)?;
                    Ok(ctx)
                }
                Identifier::PskId(_) => {
                    err!(BadIdentifier)
                }
            },
            //TODO: Implement DID logic
            _ => err(BadOneof),
        }
    }
}
