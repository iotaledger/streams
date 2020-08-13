//! `Keyload` message content. This message contains key information for the set of recipients.
//! Recipients are identified either by pre-shared keys or by NTRU public key identifiers.
//!
//! ```pb3
//! message Keyload {
//!     join link msgid;
//!     absorb byte nonce[27];
//!     skip repeated {
//!         fork;
//!         mask byte id[27];
//!         absorb external byte psk[81];
//!         commit;
//!         mask(key) byte ekey[81];
//!     }
//!     skip repeated {
//!         fork;
//!         mask byte id[27];
//!         ntrukem(key) byte ekey[3072];
//!     }
//!     absorb external byte key[81];
//!     commit;
//! }
//! fork {
//!     skip oneof {
//!         null unsigned = 0;
//!         MSSig sig = 1;
//!     }
//! }
//! ```
//!
//! # Fields:
//!
//! * `nonce` -- A nonce to be used with the key encapsulated in the keyload.
//! A unique nonce allows for session keys to be reused.
//!
//! * `id` -- Key (PSK or NTRU public key) identifier.
//!
//! * `psk` -- Pre-shared key known to the author and to a legit recipient.
//!
//! * `ekey` -- Masked session key; session key is either encrypted with spongos or with NTRU.
//!
//! * `key` -- Session key; a legit recipient gets it from `ekey`.
//!
//! * `sig` -- Optional signature; allows to authenticate keyload.
//!
//! Notes:
//! 1) Keys identities are not encrypted and may be linked to recipients identities.
//!     One possible solution is to use ephemeral NTRU keys and `mask` keys `id`s
//!     instead of `absorb`ing them. Then two keyload messages can be published consequently
//!     and identities of the latter keyload will be protected with the key from the former.
//! 2) Keyload is not authenticated (signed). It can later be implicitly authenticated
//!     via `SignedPacket`.

use anyhow::Result;
use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    prng,
    psk,
    sponge::{
        prp::PRP,
        spongos,
    },
};
use iota_streams_core_edsig::key_exchange::x25519;
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Keyload` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9KEYLOAD";

pub struct ContentWrap<'a, F, Link: HasLink, Psks, KePks> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes,
    pub key: NBytes,
    pub(crate) psks: Psks,
    pub(crate) prng: &'a prng::Prng<F>,
    pub(crate) ke_pks: KePks,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, Store, Psks, KePks> message::ContentWrap<F, Store>
    for ContentWrap<'a, F, Link, Psks, KePks>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
    KePks: Clone + ExactSizeIterator<Item = x25519::IPk<'a>>,
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
                    ctx
                        .mask(&NBytes(pskid.clone()))?
                        .absorb(External(&NBytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ke_pks)?
            .repeated(self.ke_pks.clone(), |ctx, ke_pk| {
                ctx.fork(|ctx| {
                    ctx
                        .absorb(&ke_pk.0)?
                        .x25519(&ke_pk.0, &self.key)
                })
            })?
            .absorb(External(&self.key))?
            .commit()?;
        Ok(ctx)
    }

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
                    ctx
                        .mask(&NBytes(pskid.clone()))?
                        .absorb(External(&NBytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ke_pks)?
            .repeated(self.ke_pks.clone().into_iter(), |ctx, ke_pk| {
                ctx.fork(|ctx| {
                    ctx
                        .absorb(&ke_pk.0)?
                        .x25519(&ke_pk.0, &self.key)
                })
            })?
            .absorb(External(&self.key))?
            .commit()?;
        Ok(ctx)
    }
}

//This whole mess with `'a` and `LookupArg: 'a` is needed in order to allow `LookupPsk`
//and `LookupNtruSk` avoid copying and return `&'a Psk` and `&'a NtruSk`.
pub struct ContentUnwrap<'a, F, Link: HasLink, LookupArg: 'a, LookupPsk, LookupKeSk> {
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes,
    pub(crate) lookup_arg: &'a LookupArg,
    pub(crate) lookup_psk: LookupPsk,
    pub(crate) ke_pk: x25519::PublicKey,
    pub(crate) lookup_ke_sk: LookupKeSk,
    pub(crate) ke_pks: x25519::Pks,
    pub key: NBytes,
    _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
    ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &psk::PskId) -> Option<&'b psk::Psk>,
    LookupKeSk: for<'b> Fn(&'b LookupArg, &x25519::PublicKey) -> Option<&'b x25519::StaticSecret>,
{
    pub fn new(lookup_arg: &'a LookupArg, lookup_psk: LookupPsk, lookup_ke_sk: LookupKeSk) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NBytes::zero(spongos::Spongos::<F>::NONCE_SIZE),
            lookup_arg,
            lookup_psk,
            ke_pk: x25519::PublicKey::from([0_u8; 32]),
            lookup_ke_sk,
            key: NBytes::zero(spongos::Spongos::<F>::KEY_SIZE),
            ke_pks: x25519::Pks::new(),
            _phantom: std::marker::PhantomData,
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
    LookupKeSk: for<'b> Fn(&'b LookupArg, &x25519::PublicKey) -> Option<&'b x25519::StaticSecret>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut repeated_psks = Size(0);
        let mut repeated_ke_pks = Size(0);
        let mut pskid = NBytes::zero(psk::PSKID_SIZE);
        //let mut ke_pk = NBytes::zero(x25519::PUBLIC_KEY_LENGTH);
        let mut key_found = false;
        ctx.join(store, &mut self.link)?
            .absorb(&mut self.nonce)?
            .skip(&mut repeated_psks)?
            .repeated(repeated_psks, |ctx| {
                if !key_found {
                    ctx.fork(|ctx| {
                        ctx.mask(&mut pskid)?;
                        if let Some(psk) = (self.lookup_psk)(self.lookup_arg, &pskid.0) {
                            ctx.absorb(External(&NBytes(psk.clone())))? //TODO: Get rid off clone()
                                .commit()?
                                .mask(&mut self.key)?;
                            key_found = true;
                            Ok(ctx)
                        } else {
                            // Just drop the rest of the forked message so not to waste Spongos operations
                            let n = Size(0 + 0 + spongos::Spongos::<F>::KEY_SIZE);
                            ctx.drop(n)
                        }
                    })
                } else {
                    // Drop entire fork.
                    let n = Size(psk::PSKID_SIZE + 0 + 0 + spongos::Spongos::<F>::KEY_SIZE);
                    ctx.drop(n)
                }
            })?
            .skip(&mut repeated_ke_pks)?
            .repeated(repeated_ke_pks, |ctx| {
                    ctx.fork(|ctx| {
                        ctx.absorb(&mut self.ke_pk)?;
                        self.ke_pks.insert(x25519::PublicKeyWrap(self.ke_pk));
                        if let Some(ke_sk) = (self.lookup_ke_sk)(self.lookup_arg, &self.ke_pk) {
                            ctx.x25519(ke_sk, &mut self.key)?;
                            key_found = true;
                            Ok(ctx)
                        } else {
                            // Just drop the rest of the forked message so not to waste Spongos operations
                            //TODO: key length
                            let n = Size(64);
                            ctx.drop(n)
                        }
                    })
            })?
            .guard(key_found, "Key not found")?
            .absorb(External(&self.key))?
            .commit()?;
        /*
         */
        Ok(ctx)
    }
}
