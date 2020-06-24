use anyhow::Result;

use super::Context;
use crate::{
    command::Absorb,
    types::{
        AbsorbExternalFallback,
        External,
        Fallback,
        NBytes,
    },
};

/*
/// External values are not encoded in the trinary stream.
impl<'a, F, T: 'a> Absorb<&'a External<T>> for Context<F>
where
    Self: Absorb<T>,
{
    fn absorb(&mut self, _external: &'a External<T>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the trinary stream.
impl<'a, F, T: 'a> Absorb<External<&'a T>> for Context<F>
where
//Self: Absorb<&'a T>,
{
    fn absorb(&mut self, _external: External<&'a T>) -> Result<&mut Self> {
        Ok(self)
    }
}
 */

/// External values are not encoded in the trinary stream.
impl<'a, F> Absorb<External<&'a NBytes>> for Context<F>
//where
//Self: Absorb<&'a T>,
{
    fn absorb(&mut self, _external: External<&'a NBytes>) -> Result<&mut Self> {
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>> Absorb<External<Fallback<&'a T>>> for Context<F> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}
