//! `Keyload` message content. This message contains key information for the set of recipients.
//!
//! Recipients are identified either by pre-shared keys or by Ed/X25519 public key identifiers.
//!
//! ```ddml
//! message Keyload {
//!     join link msgid;
//!     absorb u8 nonce[16];
//!     skip repeated {
//!         fork;
//!         mask u8 id[16];
//!         absorb external u8 psk[32];
//!         commit;
//!         mask u8 key[32];
//!     }
//!     skip repeated {
//!         fork;
//!         mask u8 xpk[32];
//!         absorb u8 eph_key[32];
//!         x25519(eph_key) u8 xkey[32];
//!         commit;
//!         mask u8 key[32];
//!     }
//!     absorb external u8 key[32];
//!     commit;
//! }
//! ```
//!
//! # Fields:
//!
//! * `nonce` -- A nonce to be used with the key encapsulated in the keyload.
//! A unique nonce allows for session keys to be reused.
//!
//! * `id` -- Key (PSK or X25519 public key) identifier.
//!
//! * `psk` -- Pre-shared key known to the author and to a legit recipient.
//!
//! * `xpk` -- Recipient's X25519 public key.
//!
//! * `eph_key` -- X25519 random ephemeral key.
//!
//! * `xkey` -- X25519 common key.
//!
//! * `key` -- Session key; a legit recipient gets it from corresponding fork.
//!
//! * `sig` -- Optional signature; allows to authenticate keyload.
//!
//! Notes:
//! 1) Keys identities are not encrypted and may be linked to recipients identities.
//! 2) Keyload is not authenticated (signed). It can later be implicitly authenticated
//!     via `SignedPacket`.
use crypto::keys::x25519;
use iota_streams_app::{
    id::{
        Identifier,
        UserIdentity,
    },
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
use iota_streams_core::{
    async_trait,
    prelude::{
        typenum::Unsigned as _,
        Box,
        HashMap,
        Vec,
    },
    psk,
    psk::{
        Psk,
        PskId,
        PskSize,
    },
    sponge::{
        prp::PRP,
        spongos,
    },
    Result,
};
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{
        EmptyLinkStore,
        LinkStore,
    },
    types::*,
};

use crate::Lookup;

pub struct ContentWrap<'a, F, Link>
where
    Link: HasLink,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>,
    pub key: NBytes<U32>,
    pub(crate) keys: Vec<(Identifier, Vec<u8>)>,
    pub(crate) psks: Vec<(PskId, Psk)>,
    pub(crate) user_id: &'a UserIdentity<F>,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
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
        let repeated_psks = Size(self.psks.len());
        ctx.join(&store, self.link)?.absorb(&self.nonce)?;

        // fork into new context in order to hash Identifiers
        {
            ctx.absorb(repeated_keys)?;
            // Loop through provided identifiers, masking the shared key for each one
            for (id, exchange_key) in self.keys.clone().into_iter() {
                let receiver_id = UserIdentity::from(id);
                let ctx = receiver_id.id.sizeof(ctx).await?;
                // fork in order to skip the actual keyload data which may be unavailable to all recipients
                receiver_id.encrypt_sizeof(ctx, &exchange_key, &self.key).await?;
            }

            ctx.absorb(repeated_psks)?;
            // Loop through PSK's, masking the shared key for each one
            for (pskid, psk) in self.psks.clone().into_iter() {
                ctx.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;

                ctx.absorb(External(<&NBytes<PskSize>>::from(&psk)))?
                    .commit()?
                    .mask(&self.key)?;
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
        let repeated_psks = Size(self.psks.len());
        ctx.join(store, self.link)?.absorb(&self.nonce)?;

        // fork into new context in order to hash Identifiers
        let saved_fork = ctx.spongos.fork();
        {
            ctx.absorb(repeated_keys)?;
            // Loop through provided identifiers, masking the shared key for each one
            for (id, exchange_key) in self.keys.clone().into_iter() {
                let receiver_id = UserIdentity::from(id);
                let ctx = receiver_id.id.wrap(store, ctx).await?;

                // fork in order to skip the actual keyload data which may be unavailable to all recipients
                let inner_fork = ctx.spongos.fork();
                receiver_id.encrypt(ctx, &exchange_key, &self.key).await?;
                ctx.spongos = inner_fork;
            }

            ctx.absorb(repeated_psks)?;
            // Loop through PSK's, masking the shared key for each one
            for (pskid, psk) in self.psks.clone().into_iter() {
                ctx.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;

                let inner_fork = ctx.spongos.fork();
                ctx.absorb(External(<&NBytes<PskSize>>::from(&psk)))?
                    .commit()?
                    .mask(&self.key)?;
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

pub struct ContentUnwrap<'a, F, Link, KeSkStore>
where
    Link: HasLink,
{
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>, // TODO: unify with spongos::Spongos::<F>::NONCE_SIZE)
    pub(crate) psk_store: &'a HashMap<PskId, Psk>,
    pub(crate) ke_sk_store: KeSkStore,
    pub(crate) key_ids: Vec<Identifier>,
    pub key: Option<NBytes<U32>>, // TODO: unify with spongos::Spongos::<F>::KEY_SIZE
    pub(crate) author_id: UserIdentity<F>,
    _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, 'b, F, Link, KeSkStore> ContentUnwrap<'a, F, Link, KeSkStore>
where
    F: PRP,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(psk_store: &'a HashMap<PskId, Psk>, ke_sk_store: KeSkStore, author_id: UserIdentity<F>) -> Self {
        Self {
            link: Default::default(),
            nonce: NBytes::default(),
            psk_store,
            ke_sk_store,
            key_ids: Vec::new(),
            key: None,
            author_id,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<'a, 'b, F, Link, LStore, KeSkStore> message::ContentUnwrap<F, LStore> for ContentUnwrap<'a, F, Link, KeSkStore>
where
    F: PRP + Clone,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
    LStore: LinkStore<F, Link::Rel>,
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
        let mut repeated_psks = Size(0);

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

            ctx.absorb(&mut repeated_psks)?;
            for _ in 0..repeated_psks.0 {
                let mut pskid = NBytes::<psk::PskIdSize>::default();
                ctx.mask(&mut pskid)?;
                {
                    let internal_fork = ctx.spongos.fork();
                    let mut key = NBytes::<U32>::default();
                    if let Some(psk) = self.psk_store.get(&pskid.0) {
                        ctx.absorb(External(<&NBytes<PskSize>>::from(psk)))?
                            .commit()?
                            .mask(&mut key)?;
                        self.key = Some(key);
                    } else {
                        // Just drop the rest of the forked message so not to waste Spongos operations
                        let n = Size(spongos::KeySize::<F>::USIZE);
                        ctx.drop(n)?;
                    }

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
