//! `Keyload` message _wrapping_ and _unwrapping_.
//!
//! The `Keyload` message is the means to securely exchange the encryption key of a branch with a
//! set of subscribers.
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
use alloc::{boxed::Box, vec::Vec};
use core::iter::IntoIterator;

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA
use crypto::keys::x25519;
use hashbrown::HashMap;

// Streams
use lets::{
    id::{Identifier, Identity, Permissioned, Psk, PskId},
    message::{
        self, ContentDecrypt, ContentEncrypt, ContentEncryptSizeOf, ContentSign, ContentSignSizeof, ContentVerify,
    },
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Fork, Join, Mask},
        io,
        modifiers::External,
        types::{NBytes, Size},
    },
    Spongos,
};

// Local

const NONCE_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

pub(crate) struct Wrap<'a, Subscribers, Psks> {
    initial_state: &'a mut Spongos,
    nonce: [u8; NONCE_SIZE],
    key: [u8; KEY_SIZE],
    subscribers: Subscribers,
    psks: Psks,
    author_id: &'a Identity,
}

impl<'a, Subscribers, Psks> Wrap<'a, Subscribers, Psks> {
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
        subscribers: Subscribers,
        psks: Psks,
        key: [u8; KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
        author_id: &'a Identity,
    ) -> Self
    where
        Subscribers: IntoIterator<Item = Permissioned<&'a Identifier>>,
        Subscribers::IntoIter: ExactSizeIterator,
        Psks: IntoIterator<Item = &'a (PskId, &'a Psk)> + Clone,
        Psks::IntoIter: ExactSizeIterator,
    {
        Self {
            initial_state,
            subscribers,
            psks,
            key,
            nonce,
            author_id,
        }
    }
}

#[async_trait(?Send)]
impl<'a, Subscribers, Psks> message::ContentSizeof<Wrap<'a, Subscribers, Psks>> for sizeof::Context
where
    Subscribers: IntoIterator<Item = Permissioned<&'a Identifier>> + Clone,
    Subscribers::IntoIter: ExactSizeIterator,
    Psks: IntoIterator<Item = &'a (PskId, &'a Psk)> + Clone,
    Psks::IntoIter: ExactSizeIterator,
{
    async fn sizeof(&mut self, keyload: &Wrap<'a, Subscribers, Psks>) -> Result<&mut sizeof::Context> {
        let subscribers = keyload.subscribers.clone().into_iter();
        let psks = keyload.psks.clone().into_iter();
        let n_subscribers = Size::new(subscribers.len());
        let n_psks = Size::new(psks.len());
        self.absorb(NBytes::new(keyload.nonce))?.absorb(n_subscribers)?;
        // Loop through provided identifiers, masking the shared key for each one
        for subscriber in subscribers {
            self.fork()
                .mask(subscriber)?
                .encrypt_sizeof(subscriber.identifier(), &keyload.key)
                .await?;
        }
        self.absorb(n_psks)?;
        // Loop through provided pskids, masking the shared key for each one
        for (pskid, psk) in psks {
            self.fork()
                .mask(pskid)?
                .absorb(External::new(&NBytes::new(psk)))?
                .commit()?
                .mask(NBytes::new(&keyload.key))?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign_sizeof(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, OS, Subscribers, Psks> message::ContentWrap<Wrap<'a, Subscribers, Psks>> for wrap::Context<OS>
where
    Subscribers: IntoIterator<Item = Permissioned<&'a Identifier>> + Clone,
    Subscribers::IntoIter: ExactSizeIterator,
    Psks: IntoIterator<Item = &'a (PskId, &'a Psk)> + Clone,
    Psks::IntoIter: ExactSizeIterator,
    OS: io::OStream,
{
    async fn wrap(&mut self, keyload: &mut Wrap<'a, Subscribers, Psks>) -> Result<&mut Self> {
        let subscribers = keyload.subscribers.clone().into_iter();
        let psks = keyload.psks.clone().into_iter();
        let n_subscribers = Size::new(subscribers.len());
        let n_psks = Size::new(psks.len());
        self.join(keyload.initial_state)?
            .absorb(NBytes::new(keyload.nonce))?
            .absorb(n_subscribers)?;
        // Loop through provided identifiers, masking the shared key for each one
        for subscriber in subscribers {
            self.fork()
                .mask(subscriber)?
                .encrypt(subscriber.identifier(),  &keyload.key)
                .await?;
        }
        self.absorb(n_psks)?;
        // Loop through provided pskids, masking the shared key for each one
        for (pskid, psk) in psks {
            self.fork()
                .mask(pskid)?
                .absorb(External::new(&NBytes::new(psk)))?
                .commit()?
                .mask(NBytes::new(&keyload.key))?;
        }
        self.absorb(External::new(&NBytes::new(&keyload.key)))?
            .sign(keyload.author_id)
            .await?
            .commit()?;
        Ok(self)
    }
}

pub(crate) struct Unwrap<'a> {
    initial_state: &'a mut Spongos,
    pub(crate) subscribers: Vec<Permissioned<Identifier>>,
    pub(crate) psks: Vec<PskId>,
    psk_store: &'a HashMap<PskId, Psk>,
    author_id: &'a Identifier,
    user_id: Option<&'a Identity>,
}

impl<'a> Unwrap<'a> {
    pub(crate) fn new(
        initial_state: &'a mut Spongos,
        user_id: Option<&'a Identity>,
        author_id: &'a Identifier,
        psk_store: &'a HashMap<PskId, Psk>,
    ) -> Self {
        Self {
            initial_state,
            subscribers: Vec::default(),
            psks: Vec::default(),
            psk_store,
            author_id,
            user_id,
        }
    }

    pub(crate) fn subscribers(&self) -> &[Permissioned<Identifier>] {
        &self.subscribers
    }
}

#[async_trait(?Send)]
impl<'a, IS> message::ContentUnwrap<Unwrap<'a>> for unwrap::Context<IS>
where
    IS: io::IStream,
{
    async fn unwrap(&mut self, keyload: &mut Unwrap<'a>) -> Result<&mut Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut key: Option<[u8; KEY_SIZE]> = None;
        let mut n_subscribers = Size::default();
        let mut n_psks = Size::default();
        self.join(keyload.initial_state)?
            .absorb(NBytes::new(&mut nonce))?
            .absorb(&mut n_subscribers)?;

        for _ in 0..n_subscribers.inner() {
            let mut fork = self.fork();
            // Loop through provided number of identifiers and subsequent keys
            let mut subscriber_id = Permissioned::<Identifier>::default();
            fork.mask(&mut subscriber_id)?;

            if key.is_none() && keyload.user_id.is_some() {
                let user_id = keyload.user_id.unwrap();
                if subscriber_id.identifier() == &user_id.to_identifier() {
                    fork.decrypt(user_id, key.get_or_insert([0u8; KEY_SIZE]))
                    .await?;
                } else {
                    fork.drop(KEY_SIZE + x25519::PUBLIC_KEY_LENGTH)?;
                }
            } else {
                fork.drop(KEY_SIZE + x25519::PUBLIC_KEY_LENGTH)?;
            }
            keyload.subscribers.push(subscriber_id);
        }
        self.absorb(&mut n_psks)?;

        for _ in 0..n_psks.inner() {
            let mut fork = self.fork();

            // Loop thorugh provided psks and keys
            let mut psk_id = PskId::default();
            fork.mask(&mut psk_id)?;

            if key.is_some() {
                fork.drop(KEY_SIZE)?;
            } else {
                let mut masked_key = [0u8; KEY_SIZE];
                if let Some(psk) = keyload.psk_store.get(&psk_id) {
                    fork.absorb(External::new(&NBytes::new(psk)))?
                        .commit()?
                        .mask(NBytes::new(&mut masked_key))?;
                    key = Some(masked_key);

                    keyload.psks.push(psk_id);
                } else {
                    fork.drop(KEY_SIZE)?;
                }
            }
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
