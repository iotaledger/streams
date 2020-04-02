//! Implementation of command traits for calculating the size for output buffer in Wrap operation.
use failure::ensure;
use std::iter;

use iota_streams_core::tbits::word::{BasicTbitWord, IntTbitWord, SpongosTbitWord};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

use crate::command::*;
use crate::types::*;
use failure::Fallible;

/// Message size counting context.
#[derive(Debug)]
pub struct Context<TW, F> {
    /// The current message size in trits.
    size: usize,
    _phantom: std::marker::PhantomData<(TW, F)>,
}

impl<TW, F> Context<TW, F> {
    /// Creates a new Context<TW, F>.
    pub fn new() -> Self {
        Self {
            size: 0,
            _phantom: std::marker::PhantomData,
        }
    }
    /// Returns calculated message size.
    pub fn get_size(&self) -> usize {
        self.size
    }
}

/// All Trint3 values are encoded with 3 trits.
impl<TW, F> Absorb<&Trint3> for Context<TW, F> {
    fn absorb(&mut self, _trint3: &Trint3) -> Fallible<&mut Self> {
        self.size += 3;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<TW, F> Absorb<&Size> for Context<TW, F> {
    fn absorb(&mut self, size: &Size) -> Fallible<&mut Self> {
        self.size += sizeof_sizet(size.0);
        Ok(self)
    }
}

/// All Trint3 values are encoded with 3 trits.
impl<TW, F> Absorb<Trint3> for Context<TW, F> {
    fn absorb(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        self.absorb(&trint3)
    }
}

/// Size has var-size encoding.
impl<TW, F> Absorb<Size> for Context<TW, F> {
    fn absorb(&mut self, size: Size) -> Fallible<&mut Self> {
        self.absorb(&size)
    }
}

/*
/// External values are not encoded in the trinary stream.
impl<'a, TW, F, T: 'a> Absorb<&'a External<T>> for Context<TW, F>
where
    Self: Absorb<T>,
{
    fn absorb(&mut self, _external: &'a External<T>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the trinary stream.
impl<'a, TW, F, T: 'a> Absorb<External<&'a T>> for Context<TW, F>
where
//Self: Absorb<&'a T>,
{
    fn absorb(&mut self, _external: External<&'a T>) -> Fallible<&mut Self> {
        Ok(self)
    }
}
 */

/// External values are not encoded in the trinary stream.
impl<'a, TW, F> Absorb<External<&'a NTrytes<TW>>> for Context<TW, F>
where
//Self: Absorb<&'a T>,
{
    fn absorb(&mut self, _external: External<&'a NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// `trytes` has variable size thus the size is encoded before the content trytes.
impl<'a, TW, F> Absorb<&'a Trytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn absorb(&mut self, trytes: &'a Trytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (trytes.0).size() % 3 == 0,
            "Trit size of `trytes` must be a multiple of 3."
        );
        self.size += sizeof_sizet((trytes.0).size() / 3) + (trytes.0).size();
        Ok(self)
    }
}

/// `trytes` has variable size thus the size is encoded before the content trytes.
impl<TW, F> Absorb<Trytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn absorb(&mut self, trytes: Trytes<TW>) -> Fallible<&mut Self> {
        self.absorb(&trytes)
    }
}

/// `tryte [n]` is fixed-size and is encoded with `3 * n` trits.
impl<'a, TW, F> Absorb<&'a NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn absorb(&mut self, ntrytes: &'a NTrytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (ntrytes.0).size() % 3 == 0,
            "Trit size of `tryte [n]` must be a multiple of 3."
        );
        self.size += (ntrytes.0).size();
        Ok(self)
    }
}

/// `tryte [n]` is fixed-size and is encoded with `3 * n` trits.
impl<TW, F> Absorb<NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn absorb(&mut self, ntrytes: NTrytes<TW>) -> Fallible<&mut Self> {
        self.absorb(&ntrytes)
    }
}

/// MSS public key has fixed size.
impl<'a, TW, F, P> Absorb<&'a mss::PublicKey<TW, P>> for Context<TW, F>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
{
    fn absorb(&mut self, pk: &'a mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == P::PUBLIC_KEY_SIZE);
        self.size += P::PUBLIC_KEY_SIZE;
        Ok(self)
    }
}

/// NTRU public key has fixed size.
impl<'a, TW, F> Absorb<&'a ntru::PublicKey<TW, F>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn absorb(&mut self, pk: &'a ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == ntru::PUBLIC_KEY_SIZE);
        self.size += ntru::PUBLIC_KEY_SIZE;
        Ok(self)
    }
}

/// External values are not encoded.
impl<'a, TW, F> Squeeze<&'a External<NTrytes<TW>>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn squeeze(&mut self, _external_ntrytes: &'a External<NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded.
impl<TW, F> Squeeze<&External<Mac>> for Context<TW, F> {
    fn squeeze(&mut self, _mac: &External<Mac>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// Mac is just like NTrytes.
impl<TW, F> Squeeze<&Mac> for Context<TW, F> {
    fn squeeze(&mut self, mac: &Mac) -> Fallible<&mut Self> {
        ensure!(
            mac.0 % 3 == 0,
            "Trit size of `mac` must be a multiple of 3: {}.",
            mac.0
        );
        self.size += mac.0;
        Ok(self)
    }
}

/// Mac is just like NTrytes.
impl<TW, F> Squeeze<Mac> for Context<TW, F> {
    fn squeeze(&mut self, val: Mac) -> Fallible<&mut Self> {
        self.squeeze(&val)
    }
}

/// Mask Trint3.
impl<TW, F> Mask<&Trint3> for Context<TW, F> {
    fn mask(&mut self, _val: &Trint3) -> Fallible<&mut Self> {
        self.size += 3;
        Ok(self)
    }
}

/// Mask Trint3.
impl<TW, F> Mask<Trint3> for Context<TW, F> {
    fn mask(&mut self, val: Trint3) -> Fallible<&mut Self> {
        self.mask(&val)
    }
}

/// Mask Size.
impl<TW, F> Mask<&Size> for Context<TW, F> {
    fn mask(&mut self, val: &Size) -> Fallible<&mut Self> {
        self.size += sizeof_sizet(val.0);
        Ok(self)
    }
}

/// Mask Size.
impl<TW, F> Mask<Size> for Context<TW, F> {
    fn mask(&mut self, val: Size) -> Fallible<&mut Self> {
        self.mask(&val)
    }
}

/// Mask `n` trytes.
impl<TW, F> Mask<&NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn mask(&mut self, val: &NTrytes<TW>) -> Fallible<&mut Self> {
        self.size += (val.0).size();
        Ok(self)
    }
}

/// Mask trytes, the size prefixed before the content trytes is also masked.
impl<TW, F> Mask<&Trytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn mask(&mut self, trytes: &Trytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (trytes.0).size() % 3 == 0,
            "Trit size of `trytes` must be a multiple of 3: {}.",
            (trytes.0).size()
        );
        let size = Size((trytes.0).size() / 3);
        self.mask(&size)?;
        self.size += (trytes.0).size();
        Ok(self)
    }
}

impl<TW, F> Mask<&ntru::PublicKey<TW, F>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn mask(&mut self, ntru_pk: &ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        ensure!(ntru_pk.tbits().size() == ntru::PUBLIC_KEY_SIZE);
        self.size += ntru::PUBLIC_KEY_SIZE;
        Ok(self)
    }
}

impl<TW, F, P> Mask<&mss::PublicKey<TW, P>> for Context<TW, F>
where
    TW: BasicTbitWord,
    P: mss::Parameters<TW>,
{
    fn mask(&mut self, mss_pk: &mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        ensure!(mss_pk.tbits().size() == P::PUBLIC_KEY_SIZE);
        self.size += P::PUBLIC_KEY_SIZE;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Trint3 values are encoded with 3 trits.
impl<TW, F> Skip<&Trint3> for Context<TW, F> {
    fn skip(&mut self, _trint3: &Trint3) -> Fallible<&mut Self> {
        self.size += 3;
        Ok(self)
    }
}

/// All Trint3 values are encoded with 3 trits.
impl<TW, F> Skip<Trint3> for Context<TW, F> {
    fn skip(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        self.skip(&trint3)
    }
}

/// Size has var-size encoding.
impl<TW, F> Skip<&Size> for Context<TW, F> {
    fn skip(&mut self, size: &Size) -> Fallible<&mut Self> {
        self.size += sizeof_sizet(size.0);
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<TW, F> Skip<Size> for Context<TW, F> {
    fn skip(&mut self, size: Size) -> Fallible<&mut Self> {
        self.skip(&size)
    }
}

/// `trytes` is encoded with `sizeof_sizet(n) + 3 * n` trits.
impl<'a, TW, F> Skip<&'a Trytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn skip(&mut self, trytes: &'a Trytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (trytes.0).size() % 3 == 0,
            "Trit size of `trytes` must be a multiple of 3."
        );
        self.size += sizeof_sizet((trytes.0).size() / 3) + (trytes.0).size();
        Ok(self)
    }
}

/// `trytes` is encoded with `sizeof_sizet(n) + 3 * n` trits.
impl<TW, F> Skip<Trytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn skip(&mut self, trytes: Trytes<TW>) -> Fallible<&mut Self> {
        self.skip(&trytes)
    }
}

/// `tryte [n]` is encoded with `3 * n` trits.
impl<'a, TW, F> Skip<&'a NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn skip(&mut self, ntrytes: &'a NTrytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (ntrytes.0).size() % 3 == 0,
            "Trit size of `tryte [n]` must be a multiple of 3."
        );
        self.size += (ntrytes.0).size();
        Ok(self)
    }
}

/// `tryte [n]` is encoded with `3 * n` trits.
impl<TW, F> Skip<NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn skip(&mut self, ntrytes: NTrytes<TW>) -> Fallible<&mut Self> {
        self.skip(&ntrytes)
    }
}

/// Commit costs nothing in the trinary stream.
impl<TW, F> Commit for Context<TW, F> {
    fn commit(&mut self) -> Fallible<&mut Self> {
        Ok(self)
    }
}

/// Signature size depends on Merkle tree height.
impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, &External<NTrytes<TW>>> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        sk: &mss::PrivateKey<TW, P>,
        hash: &External<NTrytes<TW>>,
    ) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == ((hash.0).0).size(),
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(sk.private_keys_left() > 0, "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with.");
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}

impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, &External<Mac>> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &mss::PrivateKey<TW, P>, hash: &External<Mac>) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == (hash.0).0,
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(sk.private_keys_left() > 0, "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with.");
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}

impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, MssHashSig> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &mss::PrivateKey<TW, P>, _hash: MssHashSig) -> Fallible<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}

/// Sizeof encapsulated secret is fixed.
impl<TW, F> Ntrukem<&ntru::PublicKey<TW, F>, &NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn ntrukem(
        &mut self,
        _key: &ntru::PublicKey<TW, F>,
        _secret: &NTrytes<TW>,
    ) -> Fallible<&mut Self> {
        //TODO: Ensure key is valid.
        //TODO: ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);
        self.size += ntru::EKEY_SIZE;
        Ok(self)
    }
}

/// Forks cost nothing in the trinary stream.
impl<TW, F, C> Fork<C> for Context<TW, F>
where
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Fallible<&mut Self> {
        cont(self)
    }
}

/// Repeated modifier. The actual number of repetitions must be wrapped
/// (absorbed/masked/skipped) explicitly.
impl<TW, F, I, C> Repeated<I, C> for Context<TW, F>
where
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: C) -> Fallible<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Fallible<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}

/*
/// It's the size of the link.
impl<'a, TW, F, L: Link> Absorb<&'a L> for Context<TW, F> {
    fn absorb(&mut self, link: &'a L) -> Fallible<&mut Self> {
        self.size += link.size();
        Ok(self)
    }
}
*/
/*
/// It's the size of the link.
impl<'a, L: Link, S: LinkStore<L>> Join<&'a L, &'a S> for Context<TW, F> {
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        self.size += link.size();
        Ok(self)
    }
}
*/

/// It's the size of the link.
impl<'a, TW, F, T: 'a + AbsorbFallback<TW, F>> Absorb<&'a Fallback<T>> for Context<TW, F> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).sizeof_absorb(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + AbsorbExternalFallback<TW, F>> Absorb<External<Fallback<&'a T>>>
    for Context<TW, F>
{
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Fallible<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + SkipFallback<TW, F>> Skip<&'a Fallback<T>> for Context<TW, F> {
    fn skip(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).sizeof_skip(self)?;
        Ok(self)
    }
}

/// It's the size of the link.
impl<'a, TW, F, L: SkipFallback<TW, F>, S: LinkStore<TW, F, L>> Join<&'a L, &'a S>
    for Context<TW, F>
{
    fn join(&mut self, _store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        link.sizeof_skip(self)?;
        Ok(self)
    }
}
/*
impl<'a, TW, F, L, S: LinkStore<TW, F, L>> Join<&'a L, &'a S> for Context<TW, F> where
    Self: Skip<&'a L>
{
    fn join(&mut self, _store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        self.skip(link)
    }
}
*/

impl<TW, F> Dump for Context<TW, F> {
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Fallible<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
