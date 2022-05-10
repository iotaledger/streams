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
            Mask,
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
            self.fork()
                .mask(identifier)?
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
    F: PRP + Clone,
    OS: io::OStream,
    // where
    //     F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    //     Link: HasLink,
    //     <Link as HasLink>::Rel: 'a + Eq +
    // SkipFallback<F>,
{
    async fn wrap(&mut self, keyload: &mut Wrap<'a, F, Subscribers>) -> Result<&mut Self> {
        let subscribers = keyload.subscribers.into_iter();
        let n_subscribers = Size::new(subscribers.len());
        self.join(keyload.initial_state)?
            .absorb(&NBytes::new(keyload.nonce))?
            .absorb(n_subscribers)?;
        // Loop through provided identifiers, masking the shared key for each one
        for (mut identifier, exchange_key) in subscribers {
            // let fork = self.fork();
            self.fork()
                .mask(&identifier)?
                .encrypt(&identifier, exchange_key, &keyload.key)
                .await?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a, F> {
    initial_state: &'a mut Spongos<F>,
    subscribers: Vec<Identifier>,
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
            subscribers: Default::default(),
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
    F: PRP + Clone,
    IS: io::IStream,
{
    async fn unwrap(&mut self, keyload: &mut Unwrap<'a, F>) -> Result<&mut Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut key = None;
        let mut n_subscribers = Size::default();
        self.join(keyload.initial_state)?
            .absorb(NBytes::new(&mut nonce))?
            .absorb(&mut n_subscribers)?;

        for _ in 0..n_subscribers.inner() {
            let mut fork = self.fork();
            // Loop through provided number of identifiers and subsequent keys
            let mut subscriber_id = Identifier::default();
            fork.mask(&mut subscriber_id)?;

            if subscriber_id == keyload.user_id.to_identifier() {
                fork.decrypt(keyload.user_id, keyload.user_ke_key, key.get_or_insert([0; KEY_SIZE]))
                    .await?;
            } else {
                // Key is meant for another subscriber, skip it
                if subscriber_id.is_psk() {
                    fork.drop(KEY_SIZE)?;
                } else {
                    fork.drop(KEY_SIZE + x25519::PUBLIC_KEY_LENGTH)?;
                }
            }
            keyload.subscribers.push(subscriber_id);
        }
        if let Some(key) = key {
            self.absorb(External::new(&NBytes::new(&key)))?
                .verify(&keyload.author_id)
                .await?;
        }
        self.commit()?;
        Ok(self)
    }
}
