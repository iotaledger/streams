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

use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    prelude::{
        typenum::Unsigned as _,
        Vec,
    },
    psk,
    sponge::{
        prp::PRP,
        spongos,
    },
    Result,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
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

pub struct ContentWrap<'a, F, Link: HasLink, Psks, KePks> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>,
    pub key: NBytes<U32>,
    pub(crate) psks: Psks,
    pub(crate) ke_pks: KePks,
    pub(crate) sig_kp: &'a ed25519::Keypair,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, Psks, KePks> message::ContentSizeof<F> for ContentWrap<'a, F, Link, Psks, KePks>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
    KePks: Clone + ExactSizeIterator<Item = (ed25519::IPk<'a>, x25519::IPk<'a>)>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        let repeated_psks = Size(self.psks.len());
        let repeated_ke_pks = Size(self.ke_pks.len());
        ctx.join(&store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx.mask(<&NBytes<psk::PskIdSize>>::from(pskid))?
                        .absorb(External(<&NBytes<psk::PskSize>>::from(psk)))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ke_pks)?
            .repeated(self.ke_pks.clone(), |ctx, (sig_pk, ke_pk)| {
                ctx.fork(|ctx| ctx.absorb(sig_pk)?.x25519(ke_pk, &self.key))
            })?
            .absorb(External(&self.key))?
            .ed25519(self.sig_kp, HashSig)?
            .commit()?;
        Ok(ctx)
    }
}

impl<'a, F, Link, Store, Psks, KePks> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link, Psks, KePks>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
    KePks: Clone + ExactSizeIterator<Item = (ed25519::IPk<'a>, x25519::IPk<'a>)>,
{
    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        let repeated_psks = Size(self.psks.len());
        let repeated_ke_pks = Size(self.ke_pks.len());
        ctx.join(store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone().into_iter(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx.mask(<&NBytes<psk::PskIdSize>>::from(pskid))?
                        .absorb(External(<&NBytes<psk::PskSize>>::from(psk)))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ke_pks)?
            .repeated(self.ke_pks.clone().into_iter(), |ctx, (sig_pk, ke_pk)| {
                ctx.fork(|ctx| ctx.absorb(sig_pk)?.x25519(ke_pk, &self.key))
            })?
            .absorb(External(&self.key))?
            .ed25519(self.sig_kp, HashSig)?
            .commit()?;
        Ok(ctx)
    }
}

// This whole mess with `'a` and `LookupArg: 'a` is needed in order to allow `LookupPsk`
// and `LookupKeSk` avoid copying and return `&'a Psk` and `&'a ed25519::PublicKey`.
pub struct ContentUnwrap<'a, F, Link: HasLink, LookupArg: 'a, LookupPsk, LookupKeSk> {
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>, // TODO: unify with spongos::Spongos::<F>::NONCE_SIZE)
    pub(crate) lookup_arg: &'a LookupArg,
    pub(crate) lookup_psk: LookupPsk,

    #[allow(dead_code)]
    pub(crate) ke_pk: ed25519::PublicKey,
    pub(crate) lookup_ke_sk: LookupKeSk,
    pub(crate) ke_pks: Vec<ed25519::PublicKey>,
    pub key: Option<NBytes<U32>>, // TODO: unify with spongos::Spongos::<F>::KEY_SIZE
    pub(crate) sig_pk: &'a ed25519::PublicKey,
    _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, LookupArg, LookupPsk, LookupKeSk> ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &psk::PskId) -> Option<&'b psk::Psk>,
    LookupKeSk: for<'b> Fn(&'b LookupArg, &ed25519::PublicKey) -> Option<&'b x25519::StaticSecret>,
{
    pub fn new(
        lookup_arg: &'a LookupArg,
        lookup_psk: LookupPsk,
        lookup_ke_sk: LookupKeSk,
        sig_pk: &'a ed25519::PublicKey,
    ) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NBytes::default(),
            lookup_arg,
            lookup_psk,
            ke_pk: ed25519::PublicKey::default(),
            lookup_ke_sk,
            ke_pks: Vec::new(),
            key: None,
            sig_pk,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store, LookupArg, LookupPsk, LookupKeSk> message::ContentUnwrap<F, Store>
    for ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
where
    F: PRP + Clone,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &psk::PskId) -> Option<&'b psk::Psk>,
    LookupKeSk: for<'b> Fn(&'b LookupArg, &ed25519::PublicKey) -> Option<&'b x25519::StaticSecret>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut repeated_psks = Size(0);
        let mut repeated_ke_pks = Size(0);
        let mut pskid = psk::PskId::default();

        ctx
            .join(store, &mut self.link)?
            .absorb(&mut self.nonce)?
            .skip(&mut repeated_psks)?
            .repeated(repeated_psks, |ctx| {
                if self.key.is_none() {
                    ctx.fork(|ctx| {
                        ctx.mask(<&mut NBytes<psk::PskIdSize>>::from(&mut pskid))?;
                        if let Some(psk) = (self.lookup_psk)(self.lookup_arg, &pskid) {
                            let mut key = NBytes::<U32>::default();
                            ctx.absorb(External(<&NBytes<psk::PskSize>>::from(psk)))?
                                .commit()?
                                .mask(&mut key)?;
                            self.key = Some(key);
                            Ok(ctx)
                        } else {
                            // Just drop the rest of the forked message so not to waste Spongos operations
                            let n = Size(spongos::KeySize::<F>::USIZE);
                            ctx.drop(n)
                        }
                    })
                } else {
                    // Drop entire fork.
                    let n = Size(psk::PSKID_SIZE + spongos::KeySize::<F>::USIZE);
                    ctx.drop(n)
                }
            })?
            .skip(&mut repeated_ke_pks)?
            .repeated(repeated_ke_pks, |ctx| {
                ctx.fork(|ctx| {
                    let mut ke_pk = ed25519::PublicKey::default();
                    ctx.absorb(&mut ke_pk)?;
                    if let Some(ke_sk) = (self.lookup_ke_sk)(self.lookup_arg, &ke_pk) {
                        let mut key = NBytes::<U32>::default();
                        ctx.x25519(ke_sk, &mut key)?;
                        self.key = Some(key);
                        // Save the relevant public key
                        self.ke_pk = ke_pk;
                        self.ke_pks.push(ke_pk);
                        Ok(ctx)
                    } else {
                        self.ke_pks.push(ke_pk);
                        // Just drop the rest of the forked message so not to waste Spongos operations
                        // TODO: key length
                        let n = Size(64);
                        ctx.drop(n)
                    }
                })
            })?
            //.guard(self.key.is_some(), "Key not found")?
        ;
        if let Some(ref key) = self.key {
            ctx.absorb(External(key))?.ed25519(self.sig_pk, HashSig)?.commit()?;
        }
        Ok(ctx)
    }
}
