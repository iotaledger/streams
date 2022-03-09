use generic_array::ArrayLength;

use super::{
    super::{
        super::types::{
            External,
            // TODO: REMOVE
            // Fallback,
            // AbsorbExternalFallback,
            NBytes,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
        Absorb,
    },
    Context,
};

impl<'a, F, T: 'a + AbsorbExternalFallback<F>> Absorb<External<Fallback<&'a T>>> for Context<F> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}
