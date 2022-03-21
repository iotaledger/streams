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
use core::convert::TryFrom;
use core::marker::PhantomData;

use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use lets::{
    id::{UserIdentifier, Identifier},
    message::{
        self,
        ContentDecrypt,
        ContentEncrypt,
        ContentEncryptSizeOf,
        ContentSign,
        ContentUnwrapNew,
        ContentVerify,
        HasLink,
    },
};
use spongos::sponge::prp::PRP;
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

pub struct ContentWrap<'a, F, Link>
where
    Link: HasLink,
{
    pub(crate) link: &'a Link::Rel,
    pub nonce: NBytes<U16>,
    pub key: NBytes<U32>,
    pub(crate) keys: Vec<(Identifier, Vec<u8>)>,
    pub(crate) user_id: &'a UserIdentity<F>,
    pub(crate) _phantom: PhantomData<(F, Link)>,
}

#[async_trait(?Send)]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        let repeated_keys = Size(self.keys.len());
        ctx.join(&store, self.link)?.absorb(&self.nonce)?;

        // fork into new context in order to hash Identifiers
        {
            ctx.absorb(repeated_keys)?;
            // Loop through provided identifiers, masking the shared key for each one
            for key_pair in self.keys.clone().into_iter() {
                let (id, exchange_key) = key_pair;
                let receiver_id = UserIdentity::from(id);
                let ctx = receiver_id.id.sizeof(ctx).await?;
                // fork in order to skip the actual keyload data which may be unavailable to all recipients
                receiver_id.encrypt_sizeof(ctx, &exchange_key, &self.key).await?;
            }
        }

        ctx.absorb(External(&self.key))?;
        // Fork for signing
        let ctx = self.user_id.sizeof(ctx).await?;
        ctx.commit()?;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        let mut id_hash = External(NBytes::<U64>::default());
        let repeated_keys = Size(self.keys.len());
        ctx.join(store, self.link)?.absorb(&self.nonce)?;

        // fork into new context in order to hash Identifiers
        let saved_fork = ctx.spongos.fork();
        {
            ctx.absorb(repeated_keys)?;
            // Loop through provided identifiers, masking the shared key for each one
            for key_pair in self.keys.clone().into_iter() {
                let (id, exchange_key) = key_pair;
                let receiver_id = UserIdentity::from(id);
                let ctx = receiver_id.id.wrap(store, ctx).await?;

                // fork in order to skip the actual keyload data which may be unavailable to all recipients
                let inner_fork = ctx.spongos.fork();
                receiver_id.encrypt(ctx, &exchange_key, &self.key).await?;
                ctx.spongos = inner_fork;
            }
            ctx.commit()?.squeeze(&mut id_hash)?;
        }
        ctx.spongos = saved_fork;

        ctx.absorb(External(&self.key))?;
        // Fork the context to sign
        let signature_fork = ctx.spongos.fork();
        let ctx = self.user_id.sign(ctx.absorb(&id_hash)?).await?;
        ctx.spongos = signature_fork;
        ctx.commit()?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link, PskStore, KeSkStore>
where
    Link: HasLink,
{
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>, // TODO: unify with spongos::Spongos::<F>::NONCE_SIZE)
    pub(crate) psk_store: PskStore,
    pub(crate) ke_sk_store: KeSkStore,
    pub(crate) key_ids: Vec<Identifier>,
    pub key: Option<NBytes<U32>>, // TODO: unify with spongos::Spongos::<F>::KEY_SIZE
    pub(crate) author_id: UserIdentity<F>,
    _phantom: PhantomData<(F, Link)>,
}

impl<'a, 'b, F, Link, PskStore, KeSkStore> ContentUnwrap<F, Link, PskStore, KeSkStore>
where
    F: PRP,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(psk_store: PskStore, ke_sk_store: KeSkStore, author_id: UserIdentity<F>) -> Self {
        Self {
            link: Default::default(),
            nonce: NBytes::default(),
            psk_store,
            ke_sk_store,
            key_ids: Vec::new(),
            key: None,
            author_id,
            _phantom: PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, 'b, F, Link, LStore, PskStore, KeSkStore> message::ContentUnwrap<F, LStore>
    for ContentUnwrap<F, Link, PskStore, KeSkStore>
where
    F: PRP + Clone,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
    LStore: LinkStore<F, Link::Rel>,
    PskStore: for<'c> Lookup<&'c Identifier, psk::Psk>,
    KeSkStore: for<'c> Lookup<&'c Identifier, x25519::SecretKey> + 'b,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &LStore,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>
    where
        IS: io::IStream,
    {
        let mut id_hash = External(NBytes::<U64>::default());
        let mut repeated_keys = Size(0);
        ctx.join(store, &mut self.link)?.absorb(&mut self.nonce)?;

        // Fork to recover identifiers
        {
            let saved_fork = ctx.spongos.fork();
            ctx.absorb(&mut repeated_keys)?;
            // Loop through provided number of identifiers and subsequent keys
            for _ in 0..repeated_keys.0 {
                let (id, ctx) = Identifier::unwrap_new(store, ctx).await?;

                // Fork in order to recover key that is meant for the recipient id
                {
                    let internal_fork = ctx.spongos.fork();
                    let sender_id = UserIdentity::from(id);
                    let mut key = NBytes::<U32>::default();
                    match &sender_id.id {
                        Identifier::PskId(_id) => {
                            if let Some(psk) = self.psk_store.lookup(&sender_id.id) {
                                sender_id.decrypt(ctx, &psk, &mut key).await?;
                                self.key = Some(key);
                            } else {
                                // Just drop the rest of the forked message so not to waste Spongos operations
                                let n = Size(spongos::KeySize::<F>::USIZE);
                                ctx.drop(n)?;
                            }
                        }
                        _ => {
                            if let Some(ke_sk) = self.ke_sk_store.lookup(&id) {
                                sender_id.decrypt(ctx, &ke_sk.to_bytes(), &mut key).await?;
                                self.key = Some(key);
                            } else {
                                // Just drop the rest of the forked message so not to waste Spongos operations
                                // TODO: key length
                                let n = Size(64);
                                ctx.drop(n)?;
                            }
                        }
                    }
                    // Save the relevant identifier
                    self.key_ids.push(sender_id.id);
                    ctx.spongos = internal_fork;
                }
            }
            ctx.commit()?.squeeze(&mut id_hash)?;
            ctx.spongos = saved_fork;
        }

        if let Some(ref key) = self.key {
            ctx.absorb(External(key))?;

            // Fork for signature verification
            let signature_fork = ctx.spongos.fork();
            let ctx = self.author_id.verify(ctx.absorb(&id_hash)?).await?;
            ctx.spongos = signature_fork;
            ctx.commit()
        } else {
            // Allow key not found, no key situation must be handled outside, there's a use-case for that
            Ok(ctx)
        }
    }
}

// TODO: add test cases: 0,1,2 pks + 0,1,2 psks + key found/notfound + unwrap modify/fuzz to check sig does work
