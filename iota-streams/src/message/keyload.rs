//! `Keyload` message _wrapping_ and _unwrapping_.
//!
//! The `Keyload` message is the means to securely exchange the encryption key of a branch with a set of subscribers.
//!
//! ```ddml
//! message Keyload {
//!     skip link msgid;
//!     join(msgid);
//!     absorb                      u8  nonce[32];
//!     absorb repeated(n):
//!       fork;
//!       match identifier:
//!         EdPubKey:
//!           mask                  u8  id_type(0);
//!           mask                  u8  ed25519_pubkey[32];
//!           x25519(pub/priv_key)  u8  x25519_pubkey[32];
//!           commit;
//!           mask                  u8  key[32];
//!         PskId:
//!           mask                  u8  id_type(1);          
//!           mask                  u8  psk_id[16];
//!           commit;
//!           mask                  u8  key[32];
//!       commit;
//!       squeeze external          u8  ids_hash[64];
//!     absorb external             u8  key[32];
//!     fork;
//!     absorb external             u8  ids_hash[64];
//!     commit;
//!     squeeze external            u8  hash[64];
//!     ed25519(hash)               u8  signature[64];
//!     commit;
//! }
//! ```
// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};
use core::{
    convert::TryFrom,
    iter::{
        FromIterator,
        IntoIterator,
    },
    marker::PhantomData,
};

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Fork,
            Join,
            Repeated,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Size,
        },
    },
    Spongos,
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
    },
    message::{
        self,
        ContentDecrypt,
        ContentEncrypt,
        ContentEncryptSizeOf,
        ContentSign,
        ContentSignSizeof,
        ContentVerify,
    },
};

// Local

// use iota_streams_core::{
//     async_trait,
//     prelude::{
//         typenum::Unsigned as _,
//         Box,
//         Vec,
//     },
//     psk,
//     sponge::{
//         prp::PRP,
//         spongos,
//     },
//     wrapped_err,
//     Errors::BadIdentifier,
//     Result,
//     WrappedError,
// };
// use iota_streams_ddml::{
//     command::*,
//     io,
//     link_store::{
//         EmptyLinkStore,
//         LinkStore,
//     },
//     types::*,
// };

// use crate::Lookup;

const NONCE_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

pub(crate) struct Wrap<'a, F, Subscribers> {
    initial_state: &'a mut Spongos<F>,
    nonce: [u8; NONCE_SIZE],
    key: [u8; KEY_SIZE],
    subscribers: Subscribers,
    author_id: &'a Identity,
}

impl<'a, F, Subscribers> Wrap<'a, F, Subscribers> {
    pub(crate) fn new(
        initial_state: &'a mut Spongos<F>,
        subscribers: Subscribers,
        key: [u8; KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
        author_id: &'a Identity,
    ) -> Self
    where
        Subscribers: IntoIterator<Item = (Identifier, &'a [u8])>,
        Subscribers::IntoIter: ExactSizeIterator,
    {
        Self {
            initial_state,
            subscribers,
            key,
            nonce,
            author_id,
        }
    }
}

#[async_trait(?Send)]
impl<'a, F, Subscribers> message::ContentSizeof<Wrap<'a, F, Subscribers>> for sizeof::Context
where
    // Subscribers: 'a,
    for<'b> &'b Subscribers: IntoIterator<Item = &'b (Identifier, &'a [u8])>,
    for<'b> <&'b Subscribers as IntoIterator>::IntoIter: ExactSizeIterator,
    // /* where
    //                                                                          * TODO: REMOVE
    //                                                                          * F: 'a + PRP, // weird 'a constraint,
    //                                                                            but compiler requires it
    //                                                                          * somehow?! L: Link,
    //                                                                          * L::Rel: 'a + Eq + SkipFallback<F>, */
{
    async fn sizeof(&mut self, keyload: &Wrap<'a, F, Subscribers>) -> Result<&mut sizeof::Context> {
        let subscribers = keyload.subscribers.into_iter();
        let n_subscribers = Size::new(subscribers.len());
        self.absorb(&NBytes::new(keyload.nonce))?.absorb(n_subscribers)?;
        // Loop through provided identifiers, masking the shared key for each one
        for (identifier, exchange_key) in subscribers {
            // TODO: WHY FORK? CAN'T WE NOT FORK AT ALL?
            // let fork = self.fork();
            self.sizeof(identifier)
                .await?
                .encrypt_sizeof(&identifier, &exchange_key, &keyload.key)
                .await?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign_sizeof(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, OS, Subscribers> message::ContentWrap<Wrap<'a, F, Subscribers>> for wrap::Context<F, OS>
where
    // Subscribers: 'a,
    for<'b> &'b Subscribers: IntoIterator<Item = &'b (Identifier, &'a [u8])>,
    for<'b> <&'b Subscribers as IntoIterator>::IntoIter: ExactSizeIterator,
    F: PRP,
    OS: io::OStream,
    // where
    //     F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    //     Link: HasLink,
    //     <Link as HasLink>::Rel: 'a + Eq +
    // SkipFallback<F>,
{
    async fn wrap(&mut self, keyload_wrap: &mut Wrap<'a, F, Subscribers>) -> Result<&mut Self> {
        let subscribers = keyload_wrap.subscribers.into_iter();
        let n_subscribers = Size::new(subscribers.len());
        self.join(keyload_wrap.initial_state)?
            .absorb(&NBytes::new(keyload_wrap.nonce))?
            .absorb(n_subscribers)?;
        // Loop through provided identifiers, masking the shared key for each one
        for (mut identifier, exchange_key) in subscribers {
            // TODO: WHY FORK? CAN'T WE NOT FORK AT ALL?
            // let fork = self.fork();
            self.wrap(&mut identifier)
                .await?
                .encrypt(&identifier, &exchange_key, &keyload_wrap.key)
                .await?;
        }
        self.absorb(External::new(&NBytes::new(&keyload_wrap.key)))?
            .sign(keyload_wrap.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    nonce: [u8; 16],
    subscribers: Vec<Identifier>,
    key: Option<[u8; 32]>,
    author_id: Identifier,
    user_id: &'a Identity,
    user_ke_key: &'a [u8],
}

impl<'a, F> Unwrap<'a, F> {
    pub(crate) fn new(
        initial_state: &'a mut Spongos<F>,
        user_id: &'a Identity,
        user_ke_key: &'a [u8],
        author_id: Identifier,
    ) -> Self {
        Self {
            initial_state,
            nonce: Default::default(),
            subscribers: Default::default(),
            key: None,
            author_id,
            user_id,
            user_ke_key,
        }
    }

    pub(crate) fn subscribers(&self) -> &[Identifier] {
        &self.subscribers
    }

    pub(crate) fn into_subscribers(self) -> Vec<Identifier> {
        self.subscribers
    }
}

#[async_trait(?Send)]
impl<'a, F, IS> message::ContentUnwrap<Unwrap<'a, F>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
    // where
    //     F: PRP + Clone,
    //     Link: HasLink,
    //     Link::Rel: Eq + Default + SkipFallback<F>,
    //     LStore: LinkStore<F, Link::Rel>,
    // PskStore: for<'c> Lookup<&'c Identifier, psk::Psk>,
    // KeSkStore: for<'c> Lookup<&'c Identifier, x25519::SecretKey> + 'b,
{
    async fn unwrap(&mut self, keyload: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        let mut hash = [0; 64];
        let mut n_subscribers = Size::default();
        self.join(&mut keyload.initial_state)?
            .absorb(&mut NBytes::new(&mut keyload.nonce))?
            .absorb(&mut n_subscribers)?;

        for _ in 0..n_subscribers.inner() {
            // Loop through provided number of identifiers and subsequent keys
            let mut subscriber_id = Identifier::default();
            self.unwrap(&mut subscriber_id).await?;

            let mut key = [0; KEY_SIZE];
            if subscriber_id == keyload.user_id.to_identifier() {
                self.decrypt(keyload.user_id, keyload.user_ke_key, &mut key).await?;
            } else {
                // Key is meant for another subscriber, skip it
                self.drop(KEY_SIZE);
            }
            keyload.subscribers.push(subscriber_id);
            // TODO: REMOVE
            // match id {
            //     Identifier::PskId(pskid) => {
            //         if let Some(psk) = keyload.psk_store.lookup(id) {
            //             id.decrypt(self, &psk, &mut key).await?;
            //             keyload.key = Some(key);
            //         } else {
            //             // Just drop the rest of the forked message so not to waste Spongos operations
            //             // let n = Size(spongos::KeySize::<F>::USIZE);
            //             self.drop(KEY_SIZE)?;
            //         }
            //     }
            //     _ => {
            //         if let Some(ke_sk) = keyload.ke_sk_store.lookup(&id) {
            //             sender_id.decrypt(self, &ke_sk.to_bytes(), &mut key).await?;
            //             keyload.key = Some(key);
            //         } else {
            //             // Just drop the rest of the forked message so not to waste Spongos operations
            //             // TODO: key length
            //             let n = Size(64);
            //             self.drop(n)?;
            //         }
            //     }
            // }
            // Save the relevant identifier
        }
        // TODO: REMOVE
        // self.commit()?.squeeze(&mut External::new(NBytes::new(hash)))?;

        self.verify(&keyload.author_id).await?.commit();
        Ok(self)
        // TODO: REMOVE
        // if let Some(key) = keyload.key {
        //     // self.absorb(External::new(key))?;
        //     // let signature_fork = self.spongos.fork();
        //     // let self = keyload.author_id.verify(self.absorb(&hash)?).await?;
        //     // self.spongos = signature_fork;
        //     // self.commit()
        // } else {
        //     // Allow key not found, no key situation must be handled outside, there's a use-case for that
        //     Ok(self)
        // }
    }
}
