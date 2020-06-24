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
use iota_streams_core_ed25519::key_exchange::x25519;
use iota_streams_protobuf3::{
    command::*,
    io,
    types::*,
};

/// Type of `Keyload` message content.
pub const TYPE: &str = "STREAMS9CHANNEL9KEYLOAD";

pub struct ContentWrap<'a, F, G, Link: HasLink, Psks, NtruPks> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes,
    pub key: NBytes,
    pub(crate) psks: Psks,
    pub(crate) prng: &'a prng::Prng<G>,
    pub(crate) ntru_pks: NtruPks,
    pub(crate) _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, F, G, Link, Store, Psks, NtruPks> message::ContentWrap<F, Store>
    for ContentWrap<'a, F, G, Link, Psks, NtruPks>
where
    F: 'a + PRP + Clone, // weird 'a constraint, but compiler requires it somehow?!
    G: PRP + Clone + Default,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
    NtruPks: Clone + ExactSizeIterator<Item = ntru::INtruPk<'a, F>>,
    //NtruPks: Clone + ExactSizeIterator<Item = &'a ntru::PublicKey<F>>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        let repeated_psks = Size(self.psks.len());
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx.join(&store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx.mask(&NBytes(pskid.clone()))?
                        .absorb(External(&NBytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ntru_pks)?
            .repeated(self.ntru_pks.clone(), |ctx, ntru_pk| {
                ctx.fork(|ctx| ctx.mask(&NBytes(ntru_pk.get_pkid().0))?.ntrukem(ntru_pk, &self.key))
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
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx.join(store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone().into_iter(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx.mask(&NBytes(pskid.clone()))?
                        .absorb(External(&NBytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ntru_pks)?
            .repeated(self.ntru_pks.clone().into_iter(), |ctx, ntru_pk| {
                ctx.fork(|ctx| {
                    ctx.mask(&NBytes(ntru_pk.get_pkid().0))?
                        .ntrukem((ntru_pk, self.prng, &self.nonce.0), &self.key)
                })
            })?
            .absorb(External(&self.key))?
            .commit()?;
        Ok(ctx)
    }
}

//This whole mess with `'a` and `LookupArg: 'a` is needed in order to allow `LookupPsk`
//and `LookupNtruSk` avoid copying and return `&'a Psk` and `&'a NtruSk`.
pub struct ContentUnwrap<'a, F, Link: HasLink, LookupArg: 'a, LookupPsk, LookupNtruSk> {
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes,
    pub(crate) lookup_arg: &'a LookupArg,
    pub(crate) lookup_psk: LookupPsk,
    pub(crate) lookup_ntru_sk: LookupNtruSk,
    pub key: NBytes,
    _phantom: std::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, LookupArg, LookupPsk, LookupNtruSk>
    ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupNtruSk>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &psk::PskId) -> Option<&'b psk::Psk>,
    LookupNtruSk: for<'b> Fn(&'b LookupArg, &ntru::Pkid) -> Option<&'b ntru::PrivateKey<F>>,
{
    pub fn new(lookup_arg: &'a LookupArg, lookup_psk: LookupPsk, lookup_ntru_sk: LookupNtruSk) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NBytes::zero(spongos::Spongos::<F>::NONCE_SIZE),
            lookup_arg,
            lookup_psk,
            lookup_ntru_sk,
            key: NBytes::zero(spongos::Spongos::<F>::KEY_SIZE),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store, LookupArg, LookupPsk, LookupNtruSk> message::ContentUnwrap<F, Store>
    for ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupNtruSk>
where
    F: PRP + Clone,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &psk::PskId) -> Option<&'b psk::Psk>,
    LookupNtruSk: for<'b> Fn(&'b LookupArg, &ntru::Pkid) -> Option<&'b ntru::PrivateKey<F>>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut repeated_psks = Size(0);
        let mut repeated_ntru_pks = Size(0);
        let mut pskid = NBytes::zero(psk::PSKID_SIZE);
        let mut ntru_pkid = NBytes::zero(ntru::PKID_SIZE);
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
            .skip(&mut repeated_ntru_pks)?
            .repeated(repeated_ntru_pks, |ctx| {
                if !key_found {
                    ctx.fork(|ctx| {
                        ctx.mask(&mut ntru_pkid)?;
                        if let Some(ntru_sk) = (self.lookup_ntru_sk)(self.lookup_arg, ntru_pkid.0.as_ref()) {
                            ctx.ntrukem(ntru_sk, &mut self.key)?;
                            key_found = true;
                            Ok(ctx)
                        } else {
                            // Just drop the rest of the forked message so not to waste Spongos operations
                            let n = Size(ntru::EKEY_SIZE);
                            ctx.drop(n)
                        }
                    })
                } else {
                    // Drop entire fork.
                    let n = Size(ntru::PKID_SIZE + ntru::EKEY_SIZE);
                    ctx.drop(n)
                }
            })?
            .guard(key_found, "Key not found")?
            .absorb(External(&self.key))?
            .commit()?;
        Ok(ctx)
    }
}
