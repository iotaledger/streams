use failure::Fallible;

use super::Context;
use crate::{
    command::Absorb,
    types::{
        AbsorbExternalFallback,
        External,
        Fallback,
        NTrytes,
    },
};

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
//where
//Self: Absorb<&'a T>,
{
    fn absorb(&mut self, _external: External<&'a NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(self)
    }
}

impl<'a, TW, F, T: 'a + AbsorbExternalFallback<TW, F>> Absorb<External<Fallback<&'a T>>> for Context<TW, F> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Fallible<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}
