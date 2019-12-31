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

use std::collections::HashMap;
use std::iter::{Iterator, ExactSizeIterator};
use std::hash::{Hash, Hasher};

use crate::app::channel::msg;
use crate::app::core::{AppInst, APPINST_SIZE, MsgId, MSGID_SIZE};
use crate::mss;
use crate::ntru;
use crate::pb3::{self, Absorb, Err, guard, Mask, Result};
use crate::prng::{self, PRNG};
use crate::psk::{self};
use crate::spongos::{self, Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

pub const TYPE: &'static str = "MAM9KEYLOAD";
pub fn sizeof(psks: &mut dyn ExactSizeIterator<Item=(&psk::PskId, &psk::Psk)>, ntrupks: &mut dyn ExactSizeIterator<Item=(&ntru::Pkid, &ntru::PublicKey)>) -> usize {
    0
    // join link msgid;
        + pb3::sizeof_ntrytes(27)
    // absorb tryte nonce[27];
        + pb3::sizeof_ntrytes(27)
    // skip repeated
        + pb3::sizeof_repeated(psks.len())
    // fork KeyloadPSK
        + psks.len() * (
            0
            // absorb tryte id[27];
                + pb3::sizeof_ntrytes(27)
            // absorb external tryte key[81];
                + 0
            // commit;
            // mask(key) tryte ekey[81];
                + pb3::sizeof_ntrytes(81)
        )
    // skip repeated
        + pb3::sizeof_repeated(ntrupks.len())
    // fork KeyloadNTRU
        + ntrupks.len() * (
            0
            // absorb tryte id[27];
                + pb3::sizeof_ntrytes(27)
            // ntrukem(pk) ekey;
                + pb3::ntrukem::sizeof_ntrukem()
        )
    // absorb external tryte key[81];
        + 0
    // commit;
        + 0
}

pub fn wrap(msgid: TritConstSlice, slink: &mut Spongos, nonce: &Trits, psks: &mut dyn ExactSizeIterator<Item=(&psk::PskId, &psk::Psk)>, ntrupks: &mut dyn ExactSizeIterator<Item=(&ntru::Pkid, &ntru::PublicKey)>, prng: &PRNG, key: &Trits, s: &mut Spongos, b: &mut TritMutSlice) {
    assert_eq!(3 * 27, nonce.size());
    assert_eq!(3 * 81, key.size());

    pb3::join::wrap_join(msgid, slink, s, b);

    nonce.wrap_absorb(s, b);

    let mut fork = Spongos::init();

    pb3::repeated(psks.len()).wrap_absorb(s, b);
    for (pskid, psk) in psks {
        s.fork_at(&mut fork);
        assert_eq!(3 * 27, pskid.size());
        pskid.wrap_absorb(&mut fork, b);
        assert_eq!(3 * 81, psk.size());
        fork.absorb(psk.slice());
        fork.commit();
        key.wrap_mask(&mut fork, b);
    }

    pb3::repeated(ntrupks.len()).wrap_absorb(s, b);
    for (ntrupkid, ntrupk) in ntrupks {
        s.fork_at(&mut fork);
        pb3::wrap_absorb_trits(ntrupkid.slice(), &mut fork, b);
        //TODO: Use another `nonce` for ntru_encr.
        pb3::ntrukem::wrap_ntrukem(key.slice(), ntrupk, &prng, nonce.slice(), &mut fork, b);
    }

    s.absorb(key.slice());
    s.commit();
}

pub fn unwrap(lookup_link: impl Fn(TritConstSlice) -> Option<(Spongos, ())>, psks: &HashMap<psk::PskId, psk::Psk>, ntrusks: &HashMap<ntru::Pkid, ntru::PrivateKey>, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    pb3::join::unwrap_join(lookup_link, s, b)?;
    pb3::unwrap_absorb_n(81, s, b)?;

    let mut key = Trits::zero(spongos::KEY_SIZE);
    let mut key_found = false;
    let mut fork = Spongos::init();

    {
        let psks_count = pb3::Repeated::unwrap_absorb_sized(s, b)?;
        let mut pskid = Trits::zero(psk::PSKID_SIZE);

        let mut n: usize = 0;
        loop {
            if key_found || n == psks_count.0 {
                break;
            }
            n += 1;

            s.fork_at(&mut fork);
            pskid.unwrap_absorb(&mut fork, b)?;
            if let Some(psk) = psks.get(&pskid) {
                fork.absorb(psk.slice());
                fork.commit();
                key.unwrap_mask(&mut fork, b)?;
                key_found = true;
            } else {
                b.advance(pb3::sizeof_ntrytes(81));
            }
        }

        let sizeof_keyloadpsk = pb3::sizeof_ntrytes(27) + pb3::sizeof_ntrytes(81);
        b.advance((psks_count.0 - n) * sizeof_keyloadpsk);
    }

    {
        let ntrus_count = pb3::Repeated::unwrap_absorb_sized(s, b)?;
        let mut ntrupkid = Trits::zero(ntru::PKID_SIZE);

        let mut n: usize = 0;
        loop {
            if key_found || n == ntrus_count.0 {
                break;
            }
            n += 1;

            s.fork_at(&mut fork);
            ntrupkid.unwrap_absorb(&mut fork, b)?;
            if let Some(ntrusk) = ntrusks.get(&ntrupkid) {
                pb3::ntrukem::unwrap_ntrukem(key.mut_slice(), ntrusk, &mut fork, b)?;
                key_found = true;
            } else {
                b.advance(pb3::ntrukem::sizeof_ntrukem());
            }
        }

        let sizeof_keyloadntru = pb3::sizeof_ntrytes(27) + pb3::ntrukem::sizeof_ntrukem();
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

    #[test]
    fn simple() {
        let prng = prng::dbg_init_str("PRNGKEY");
        let key = prng.gen_trits(&Trits::from_str("ABC").unwrap(), spongos::KEY_SIZE);
        let msgid = Trits::cycle_str(81, "MSGID");

        let mut psks: HashMap<psk::PskId, psk::Psk> = HashMap::new();
        let mut pskid = Trits::zero(psk::PSKID_SIZE);
        let psk = Trits::zero(psk::PSK_SIZE);
        psks.insert(pskid.clone(), psk.clone());
        /*
        pskid.mut_slice().inc();
        prng.gen(pskid.slice(), psk.mut_slice());
        psks.insert(pskid.clone(), psk.clone());
        pskid.mut_slice().inc();
        prng.gen(pskid.slice(), psk.mut_slice());
        psks.insert(pskid.clone(), psk.clone());
         */

        let mut nonce = Trits::zero(81);

        let mut msssk = mss::PrivateKey::gen(&prng, 1, nonce.slice());

        let mut ntrupks: HashMap<ntru::Pkid, ntru::PublicKey> = HashMap::new();
        let mut ntrusks: HashMap<ntru::Pkid, ntru::PrivateKey> = HashMap::new();
        let mut ntrupkid = ntru::Pkid::zero(ntru::PKID_SIZE);
        for _ in 0..5 {
            let (ntrusk, ntrupk) = ntru::gen(&prng, nonce.slice());
            nonce.mut_slice().inc();
            ntrupk.id().copy(ntrupkid.mut_slice());
            ntrupks.insert(ntrupkid.clone(), ntrupk.clone());
            ntrusks.insert(ntrupkid.clone(), ntrusk.clone());
        }
        
        let n = 0
            + msg::keyload::sizeof(&mut psks.iter(), &mut ntrupks.iter())
            + pb3::mssig::sizeof_mssig(&msssk)
            ;
        let mut buf = Trits::zero(n);
        let slink = Spongos::init();

        {
            let mut s = Spongos::init();
            let mut b = buf.mut_slice();
            msg::keyload::wrap(msgid.slice(), &mut slink.clone(), &nonce, &mut psks.iter(), &mut ntrupks.iter(), &prng, &key, &mut s, &mut b);
            pb3::mssig::squeeze_wrap_mssig(&msssk, &mut s, &mut b);
            msssk.next();
            assert!(b.size() == 0);
        }

        let lookup_link = |_m| Some((slink.clone(), ()));

        // unwrap using psks
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r0 = msg::keyload::unwrap(lookup_link, &psks, &ntrusks, &mut s, &mut b);
            assert!(r0 == Ok(()));
            let r1 = pb3::mssig::squeeze_unwrap_mssig_verify(&msssk.public_key(), &mut s, &mut b);
            assert!(r1 == Ok(()));
            assert!(b.size() == 0);
        }

        // unwrap using ntrusks
        {
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let psks2: HashMap<psk::PskId, psk::Psk> = HashMap::new();
            let r0 = msg::keyload::unwrap(lookup_link, &psks2, &ntrusks, &mut s, &mut b);
            assert!(r0 == Ok(()));
            let r1 = pb3::mssig::squeeze_unwrap_mssig_verify(&msssk.public_key(), &mut s, &mut b);
            assert!(r1 == Ok(()));
            assert!(b.size() == 0);
        }

        // modify psks, unwrap should fail
        {
            let mut psks2 = psks.clone();
            for (_, psk) in psks2.iter_mut() {
                psk.mut_slice().inc();
            }
            let mut s = Spongos::init();
            let mut b = buf.slice();
            let r0 = msg::keyload::unwrap(lookup_link, &psks2, &ntrusks, &mut s, &mut b);
            assert!(r0 == Ok(()));
            let r1 = pb3::mssig::squeeze_unwrap_mssig_verify(&msssk.public_key(), &mut s, &mut b);
            assert!(r1 != Ok(()));
            assert!(b.size() == 0);
        }
    }
}
