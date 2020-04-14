use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Skip,
    types::{
        sizeof_sizet,
        Fallback,
        NTrytes,
        Size,
        SkipFallback,
        Trint3,
        Trytes,
    },
};
use iota_streams_core::tbits::word::BasicTbitWord;

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

impl<'a, TW, F, T: 'a + SkipFallback<TW, F>> Skip<&'a Fallback<T>> for Context<TW, F> {
    fn skip(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).sizeof_skip(self)?;
        Ok(self)
    }
}
