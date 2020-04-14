use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Mask,
    types::{
        sizeof_sizet,
        NTrytes,
        Size,
        Trint3,
        Trytes,
    },
};
use iota_streams_core::tbits::word::BasicTbitWord;
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

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
