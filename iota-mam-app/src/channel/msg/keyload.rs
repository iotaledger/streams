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
use iota_mam_protobuf3::{command::*, io, types::*, sizeof, wrap, unwrap};
use crate::Result;
use crate::core::HasLink;

/// Type of `Keyload` message content.
pub const TYPE: &str = "MAM9CHANNEL9KEYLOAD";

pub struct ContentWrap<'a, RelLink: 'a, Store: 'a, Psks, NtruPks> {
    pub(crate) store: &'a Store,
    pub(crate) link: &'a RelLink,
    pub(crate) nonce: NTrytes,
    pub(crate) key: NTrytes,
    pub(crate) psks: Psks,
    pub(crate) prng: &'a prng::PRNG,
    pub(crate) ntru_pks: NtruPks,
}

impl<'a, RelLink: 'a, Store: 'a, Psks, NtruPks> ContentWrap<'a, RelLink, Store, Psks, NtruPks> where
    RelLink: Eq + SkipFallback,
    Store: LinkStore<RelLink>,
    Psks: Clone + ExactSizeIterator<Item = (&'a psk::PskId, &'a psk::Psk)>,
    NtruPks: Clone + ExactSizeIterator<Item = (&'a ntru::Pkid, &'a ntru::PublicKey)>,
{
    pub(crate) fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context) -> Result<&'c mut sizeof::Context> {
        let repeated_psks = Size(self.psks.len());
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx
            .join(self.store, self.link)?
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
    pub(crate) fn wrap<'c, OS: io::OStream>(&self, ctx: &'c mut wrap::Context<OS>) -> Result<&'c mut wrap::Context<OS>> {
        let repeated_psks = Size(self.psks.len());
        let repeated_ntru_pks = Size(self.ntru_pks.len());
        ctx
            .join(self.store, self.link)?
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

pub struct ContentUnwrap<'a, RelLink, Store, LookupPsk, LookupNtruSk> {
    pub(crate) store: &'a Store,
    pub(crate) link: RelLink,
    pub(crate) nonce: NTrytes,
    pub(crate) lookup_psk: LookupPsk,
    pub(crate) lookup_ntru_sk: LookupNtruSk,
    pub(crate) key: NTrytes,
}

impl<'a, RelLink: 'a, Store: 'a, LookupPsk, LookupNtruSk> ContentUnwrap<'a, RelLink, Store, LookupPsk, LookupNtruSk> where
    RelLink: Eq + Default + SkipFallback,
    Store: LinkStore<RelLink>,
    LookupPsk: Fn(&psk::PskId) -> Option<&'a psk::Psk>,
    LookupNtruSk: Fn(&ntru::Pkid) -> Option<&'a ntru::PrivateKey>,
{
    pub fn new(store: &'a Store, lookup_psk: LookupPsk, lookup_ntru_sk: LookupNtruSk) -> Self {
        Self {
            store: store,
            link: RelLink::default(),
            nonce: NTrytes::zero(27 * 3), //TODO: spongos::NONCE_SIZE?
            lookup_psk: lookup_psk,
            lookup_ntru_sk: lookup_ntru_sk,
            key: NTrytes::zero(ntru::KEY_SIZE),
        }
    }

    pub(crate) fn unwrap<'c, IS: io::IStream>(&mut self, ctx: &'c mut unwrap::Context<IS>) -> Result<&'c mut unwrap::Context<IS>> {
        let mut repeated_psks = Size(0);
        let mut repeated_ntru_pks = Size(0);
        let mut pskid = NTrytes::zero(psk::PSKID_SIZE);
        let mut psk = NTrytes::zero(psk::PSK_SIZE);
        let mut ntru_pkid = NTrytes::zero(ntru::PKID_SIZE);
        let mut key_found = false;

        ctx
            .join(self.store, &mut self.link)?
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

/*
use std::collections::HashMap;
use std::iter::ExactSizeIterator;

use iota_mam_core::{key_encapsulation::ntru, prng::PRNG, psk, spongos::{self, Spongos}, trits::{TritSlice, TritSliceMut, Trits}};
use iota_mam_protobuf3::protobuf3::{self, guard, Absorb, Err, Mask, Result};

use crate::core::{MsgId, MSGID_SIZE};

pub const TYPE: &str = "MAM9KEYLOAD";
pub fn sizeof<'a, Psks, NtruPks>(psks: Psks, ntrupks: NtruPks) -> usize where
    Psks: ExactSizeIterator<Item = (&'a psk::PskId, &'a psk::Psk)>,
    NtruPks: ExactSizeIterator<Item = (&'a ntru::Pkid, &'a ntru::PublicKey)>,
{
    0
    // join link msgid;
        + protobuf3::sizeof_ntrytes(27)
    // absorb tryte nonce[27];
        + protobuf3::sizeof_ntrytes(27)
    // skip repeated
        + protobuf3::sizeof_repeated(psks.len())
    // fork KeyloadPSK
        + psks.len() * (
            0
            // absorb tryte id[27];
                + protobuf3::sizeof_ntrytes(27)
            // absorb external tryte key[81];
                + 0
            // commit;
            // mask(key) tryte ekey[81];
                + protobuf3::sizeof_ntrytes(81)
        )
    // skip repeated
        + protobuf3::sizeof_repeated(ntrupks.len())
    // fork KeyloadNTRU
        + ntrupks.len() * (
            0
            // absorb tryte id[27];
                + protobuf3::sizeof_ntrytes(27)
            // ntrukem(pk) ekey;
                + protobuf3::ntrukem::sizeof_ntrukem()
        )
    // absorb external tryte key[81];
        + 0
    // commit;
        + 0
}

pub fn wrap<'a, Psks, NtruPks>(
    msgid: &MsgId,
    slink: &mut Spongos,
    nonce: &Trits,
    psks: Psks,
    ntrupks: NtruPks,
    prng: &PRNG,
    key: &Trits,
    s: &mut Spongos,
    b: &mut TritSliceMut,
) where
    Psks: ExactSizeIterator<Item = (&'a psk::PskId, &'a psk::Psk)>,
    NtruPks: ExactSizeIterator<Item = (&'a ntru::Pkid, &'a ntru::PublicKey)>,
{
    assert_eq!(3 * 27, nonce.size());
    assert_eq!(3 * 81, key.size());

    protobuf3::join::wrap_join(msgid.id.slice(), slink, s, b);

    nonce.wrap_absorb(s, b);

    let mut fork = Spongos::init();

    protobuf3::repeated(psks.len()).wrap_absorb(s, b);
    for (pskid, psk) in psks {
        s.fork_at(&mut fork);
        assert_eq!(3 * 27, pskid.size());
        pskid.wrap_absorb(&mut fork, b);
        assert_eq!(3 * 81, psk.size());
        fork.absorb(psk.slice());
        fork.commit();
        key.wrap_mask(&mut fork, b);
    }

    protobuf3::repeated(ntrupks.len()).wrap_absorb(s, b);
    for (ntrupkid, ntrupk) in ntrupks {
        s.fork_at(&mut fork);
        protobuf3::wrap_absorb_trits(ntrupkid.slice(), &mut fork, b);
        //TODO: Use another `nonce` for ntru_encr.
        protobuf3::ntrukem::wrap_ntrukem(key.slice(), ntrupk, &prng, nonce.slice(), &mut fork, b);
    }

    s.absorb(key.slice());
    s.commit();
}

pub fn unwrap<'b, 'c, LookupLink, LookupPsk, LookupNtruSk>(lookup_link: LookupLink, lookup_psk: LookupPsk, lookup_ntrusk: LookupNtruSk, s: &mut Spongos, b: &mut TritSlice) -> Result<()> where
    LookupLink: Fn(TritSlice) -> Option<(Spongos, ())>,
    LookupPsk: for <'a> Fn(&'a psk::PskId) -> Option<&'b psk::Psk>,
    LookupNtruSk: for <'a> Fn(&'a ntru::Pkid) -> Option<&'c ntru::PrivateKey>,
{
    protobuf3::join::unwrap_join(lookup_link, s, b)?;
    protobuf3::unwrap_absorb_n(81, s, b)?;

    let mut key = Trits::zero(spongos::KEY_SIZE);
    let mut key_found = false;
    let mut fork = Spongos::init();

    {
        let psks_count = protobuf3::Repeated::unwrap_absorb_sized(s, b)?;
        let mut pskid = Trits::zero(psk::PSKID_SIZE);

        let mut n: usize = 0;
        loop {
            if key_found || n == psks_count.0 {
                break;
            }
            n += 1;

            s.fork_at(&mut fork);
            pskid.unwrap_absorb(&mut fork, b)?;
            if let Some(psk) = lookup_psk(&pskid) {
                fork.absorb(psk.slice());
                fork.commit();
                key.unwrap_mask(&mut fork, b)?;
                key_found = true;
            } else {
                b.advance(protobuf3::sizeof_ntrytes(81));
            }
        }

        let sizeof_keyloadpsk = protobuf3::sizeof_ntrytes(27) + protobuf3::sizeof_ntrytes(81);
        b.advance((psks_count.0 - n) * sizeof_keyloadpsk);
    }

    {
        let ntrus_count = protobuf3::Repeated::unwrap_absorb_sized(s, b)?;
        let mut ntrupkid = Trits::zero(ntru::PKID_SIZE);

        let mut n: usize = 0;
        loop {
            if key_found || n == ntrus_count.0 {
                break;
            }
            n += 1;

            s.fork_at(&mut fork);
            ntrupkid.unwrap_absorb(&mut fork, b)?;
            if let Some(ntrusk) = lookup_ntrusk(&ntrupkid) {
                protobuf3::ntrukem::unwrap_ntrukem(key.slice_mut(), ntrusk, &mut fork, b)?;
                key_found = true;
            } else {
                b.advance(protobuf3::ntrukem::sizeof_ntrukem());
            }
        }

        let sizeof_keyloadntru = protobuf3::sizeof_ntrytes(27) + protobuf3::ntrukem::sizeof_ntrukem();
        b.advance((ntrus_count.0 - n) * sizeof_keyloadntru);
    }

    guard(key_found, Err::KeyNotFound)?;
    s.absorb(key.slice());
    s.commit();
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::channel::msg;
    use iota_mam_core::{signature::mss, prng, trits::Trits};

    #[test]
    fn simple() {
        let prng = prng::dbg_init_str("PRNGKEY");
        let key = prng.gen_trits(&Trits::from_str("ABC").unwrap(), spongos::KEY_SIZE);
        let msgid = MsgId {
            id: Trits::cycle_str(MSGID_SIZE, "MSGID"),
        };

        let mut psks: HashMap<psk::PskId, psk::Psk> = HashMap::new();
        let pskid = Trits::zero(psk::PSKID_SIZE);
        let psk = Trits::zero(psk::PSK_SIZE);
        psks.insert(pskid, psk);
        /*
        pskid.slice_mut().inc();
        prng.gen(pskid.slice(), psk.slice_mut());
        psks.insert(pskid.clone(), psk.clone());
        pskid.slice_mut().inc();
        prng.gen(pskid.slice(), psk.slice_mut());
        psks.insert(pskid.clone(), psk.clone());
         */

        let mut nonce = Trits::zero(81);

        let mut mss_sk = mss::PrivateKey::<>::gen(&prng, nonce.slice(), 1);

        let mut ntrupks: HashMap<ntru::Pkid, ntru::PublicKey> = HashMap::new();
        let mut ntrusks: HashMap<ntru::Pkid, ntru::PrivateKey> = HashMap::new();
        let mut ntrupkid = ntru::Pkid::zero(ntru::PKID_SIZE);
        for _ in 0..5 {
            let (ntrusk, ntrupk) = ntru::gen(&prng, nonce.slice());
            nonce.slice_mut().inc();
            ntrupk.id().copy(ntrupkid.slice_mut());
            ntrupks.insert(ntrupkid.clone(), ntrupk.clone());
            ntrusks.insert(ntrupkid.clone(), ntrusk.clone());
        }

        let n = 0
            + msg::keyload::sizeof(&mut psks.iter(), &mut ntrupks.iter())
            + protobuf3::mssig::sizeof_mssig(&mss_sk);
        let mut buf = Trits::zero(n);
        let slink = Spongos::init();

        {
            let mut s = Spongos::init();
            let mut b = buf.slice_mut();
            msg::keyload::wrap(
                &msgid,
                &mut slink.clone(),
                &nonce,
                &mut psks.iter(),
                &mut ntrupks.iter(),
                &prng,
                &key,
                &mut s,
                &mut b,
            );
            protobuf3::mssig::squeeze_wrap_mssig(&mss_sk, &mut s, &mut b);
            mss_sk.next();
            assert!(b.size() == 0);
        }

        let lookup_link = |_m: TritSlice| Some((slink.clone(), ()));
        let lookup_ntrusk = |ntrupkid: &ntru::Pkid| ntrusks.get(ntrupkid);

        // unwrap using psks
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let lookup_psk = |pskid: &psk::PskId| psks.get(pskid);
            let r0 = msg::keyload::unwrap(lookup_link, lookup_psk, lookup_ntrusk, &mut s, &mut b);
            assert!(r0.is_ok());
            let r1 = protobuf3::mssig::squeeze_unwrap_mssig_verify(mss_sk.public_key(), &mut s, &mut b);
            assert!(r1.is_ok());
            assert!(b.size() == 0);
        }

        // unwrap using ntrusks
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let psks2: HashMap<psk::PskId, psk::Psk> = HashMap::new();
            let lookup_psk2 = |pskid: &psk::PskId| psks2.get(pskid);
            let r0 = msg::keyload::unwrap(lookup_link, lookup_psk2, lookup_ntrusk, &mut s, &mut b);
            assert!(r0.is_ok());
            let r1 = protobuf3::mssig::squeeze_unwrap_mssig_verify(mss_sk.public_key(), &mut s, &mut b);
            assert!(r1.is_ok());
            assert!(b.size() == 0);
        }

        // modify psks, unwrap should fail
        {
            let mut psks2 = psks;
            for (_, psk) in psks2.iter_mut() {
                psk.slice_mut().inc();
            }
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let lookup_psk2 = |pskid: &psk::PskId| psks2.get(pskid);
            let r0 = msg::keyload::unwrap(lookup_link, lookup_psk2, lookup_ntrusk, &mut s, &mut b);
            assert!(r0.is_ok());
            let r1 = protobuf3::mssig::squeeze_unwrap_mssig_verify(mss_sk.public_key(), &mut s, &mut b);
            assert!(!r1.is_ok());
            assert!(b.size() == 0);
        }
    }
}
 */
