use anyhow::ensure;
use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{
                Context,
                Unwrap,
            },
            Squeeze,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Mac,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
    error::Error::BadMac,
};
impl<'a, F: PRP, IS: io::IStream> Squeeze<&'a Mac> for Context<F, IS> {
    fn squeeze(&mut self, val: &'a Mac) -> Result<&mut Self> {
        ensure!(self.spongos.squeeze_eq(self.stream.try_advance(val.length())?), BadMac);
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Squeeze<Mac> for Context<F, IS> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS> Squeeze<&'a mut External<NBytes<N>>> for Context<F, IS> {
    fn squeeze(&mut self, val: &'a mut External<NBytes<N>>) -> Result<&mut Self> {
        self.spongos.squeeze_mut(val);
        Ok(self)
    }
}

// Implement &mut External<T> for any External<&mut T> implementation
impl<'a, T, F, OS> Squeeze<&'a mut External<T>> for Context<F, OS> where Self: Squeeze<External<&'a mut T>> {
    fn squeeze(&mut self, external: &'a mut External<T>) -> Result<&mut Self> {
        self.squeeze(External::new(external.inner_mut()))
    }
}
