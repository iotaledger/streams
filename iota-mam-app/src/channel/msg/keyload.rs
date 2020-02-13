//! `Keyload` message content. This message contains key information for the set of recipients.
//! Recipients are identified either by pre-shared keys or by NTRU public key identifiers.
//!
//! ```pb3
//! message Keyload {
//!     join link msgid;
//!     absorb tryte nonce[27];
//!     skip repeated {
//!         fork;
//!         mask tryte id[27];
//!         absorb external tryte psk[81];
//!         commit;
//!         mask(key) tryte ekey[81];
//!     }
//!     skip repeated {
//!         fork;
//!         mask tryte id[27];
//!         ntrukem(key) tryte ekey[3072];
//!     }
//!     absorb external tryte key[81];
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

use failure::bail;

use iota_mam_core::{signature::mss, key_encapsulation::ntru, psk, prng};
use iota_mam_protobuf3::{command::*, io, types::*};
use crate::Result;
use crate::core::HasLink;
use crate::core::msg;

/// Type of `Keyload` message content.
pub const TYPE: &str = "MAM9CHANNEL9KEYLOAD";

pub struct ContentWrap<'a, Link: HasLink, Psks, NtruPks> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) nonce: NTrytes,
    pub(crate) key: NTrytes,
    pub(crate) psks: Psks,
    pub(crate) prng: &'a prng::PRNG,
    pub(crate) ntru_pks: NtruPks,
    pub(crate) _phantom: std::marker::PhantomData<Link>,
}

impl<'a, Link, Store, Psks, NtruPks> msg::ContentWrap<Store> for ContentWrap<'a, Link, Psks, NtruPks> where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
    Psks: Clone + ExactSizeIterator<Item = (&'a psk::PskId, &'a psk::Psk)>,
    NtruPks: Clone + ExactSizeIterator<Item = (&'a ntru::Pkid, &'a ntru::PublicKey)>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        let store = EmptyLinkStore::<<Link as HasLink>::Rel, ()>::default();
        let repeated_psks = Size(self.psks.len());
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx
            .join(&store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone().into_iter(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx
                        .mask(&NTrytes(pskid.clone()))?
                        .absorb(External(&NTrytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ntru_pks)?
            .repeated(self.ntru_pks.clone().into_iter(), |ctx, (ntru_pkid, ntru_pk)| {
                ctx.fork(|ctx| {
                    ctx
                        .mask(&NTrytes(ntru_pkid.clone()))?
                        .ntrukem(ntru_pk, &self.key)
                })
            })?
            .absorb(External(&self.key))?
            .commit()?
        ;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(&self, store: &Store, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        let repeated_psks = Size(self.psks.len());
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx
            .join(store, self.link)?
            .absorb(&self.nonce)?
            .skip(repeated_psks)?
            .repeated(self.psks.clone().into_iter(), |ctx, (pskid, psk)| {
                ctx.fork(|ctx| {
                    ctx
                        .mask(&NTrytes(pskid.clone()))?
                        .absorb(External(&NTrytes(psk.clone())))?
                        .commit()?
                        .mask(&self.key)
                })
            })?
            .skip(repeated_ntru_pks)?
            .repeated(self.ntru_pks.clone().into_iter(), |ctx, (ntru_pkid, ntru_pk)| {
                ctx.fork(|ctx| {
                    ctx
                        .mask(&NTrytes(ntru_pkid.clone()))?
                        .ntrukem((ntru_pk, self.prng, &self.nonce.0), &self.key)
                })
            })?
            .absorb(External(&self.key))?
            .commit()?
        ;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink, LookupPsk, LookupNtruSk> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) nonce: NTrytes,
    pub(crate) lookup_psk: LookupPsk,
    pub(crate) lookup_ntru_sk: LookupNtruSk,
    pub(crate) key: NTrytes,
}

impl<Link, LookupPsk, LookupNtruSk> ContentUnwrap<Link, LookupPsk, LookupNtruSk> where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    LookupPsk: for<'a> Fn(&'a psk::PskId) -> Option<&'a psk::Psk>,
    LookupNtruSk: for<'a> Fn(&'a ntru::Pkid) -> Option<&'a ntru::PrivateKey>,
{
    pub fn new(lookup_psk: LookupPsk, lookup_ntru_sk: LookupNtruSk) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NTrytes::zero(27 * 3), //TODO: spongos::NONCE_SIZE?
            lookup_psk: lookup_psk,
            lookup_ntru_sk: lookup_ntru_sk,
            key: NTrytes::zero(ntru::KEY_SIZE),
        }
    }
}

impl<Link, Store, LookupPsk, LookupNtruSk> msg::ContentUnwrap<Store> for ContentUnwrap<Link, LookupPsk, LookupNtruSk> where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
    LookupPsk: for<'a> Fn(&'a psk::PskId) -> Option<&'a psk::Psk>,
    LookupNtruSk: for<'a> Fn(&'a ntru::Pkid) -> Option<&'a ntru::PrivateKey>,
{
    fn unwrap<'c, IS: io::IStream>(&mut self, store: &Store, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        let mut repeated_psks = Size(0);
        let mut repeated_ntru_pks = Size(0);
        let mut pskid = NTrytes::zero(psk::PSKID_SIZE);
        let mut psk = NTrytes::zero(psk::PSK_SIZE);
        let mut ntru_pkid = NTrytes::zero(ntru::PKID_SIZE);
        let mut key_found = false;

        ctx
            .join(store, &mut self.link)?
            .absorb(&mut self.nonce)?
            .skip(&mut repeated_psks)?
            .repeated(repeated_psks, |ctx| {
                if !key_found {
                    ctx.fork(|ctx| {
                        ctx.mask(&mut pskid)?;
                        if let Some(psk) = (self.lookup_psk)(&pskid.0) {
                            ctx
                                .absorb(External(&NTrytes(psk.clone())))? //TODO: Get rid off clone()
                                .commit()?
                                .mask(&mut self.key)?
                            ;
                            key_found = true;
                            Ok(ctx)
                        } else {
                            // Just drop the rest of the forked message so not to waste Spongos operations
                            let n = Size(0 + 0 + ntru::KEY_SIZE);
                            ctx.drop(n)
                        }
                    })
                } else {
                    // Drop entire fork.
                    let n = Size(psk::PSKID_SIZE + 0 + 0 + ntru::KEY_SIZE);
                    ctx.drop(n)
                }
            })?
            .skip(&mut repeated_ntru_pks)?
            .repeated(repeated_ntru_pks, |ctx| {
                if !key_found {
                    ctx.fork(|ctx| {
                        ctx.mask(&mut ntru_pkid)?;
                        if let Some(ntru_sk) = (self.lookup_ntru_sk)(&ntru_pkid.0) {
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
            .absorb(External(&self.key))?
            .commit()?
        ;
        Ok(ctx)
    }
}
