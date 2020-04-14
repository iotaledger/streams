use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Absorb,
    types::{
        sizeof_sizet,
        AbsorbFallback,
        Fallback,
        NTrytes,
        Size,
        Trint3,
        Trytes,
    },
};
use iota_streams_core::tbits::word::BasicTbitWord;
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

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

/*
/// It's the size of the link.
impl<'a, TW, F, L: Link> Absorb<&'a L> for Context<TW, F> {
    fn absorb(&mut self, link: &'a L) -> Fallible<&mut Self> {
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
