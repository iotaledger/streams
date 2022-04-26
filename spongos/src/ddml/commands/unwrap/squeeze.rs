use anyhow::{
    ensure,
    Result,
};
use generic_array::ArrayLength;

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
            Mac,
            NBytes,
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

impl<'a, F: PRP, T: AsMut<[u8]>, IS> Squeeze<External<NBytes<&'a mut T>>> for Context<F, IS> {
    fn squeeze(&mut self, val: External<NBytes<&'a mut T>>) -> Result<&mut Self> {
        self.spongos.squeeze_mut(val);
        Ok(self)
    }
}

impl<'a, F: PRP, T, IS> Squeeze<External<&'a mut NBytes<T>>> for Context<F, IS>
where
    Self: Squeeze<External<NBytes<&'a mut T>>>,
{
    fn squeeze(&mut self, external_nbytes: External<&'a mut NBytes<T>>) -> Result<&mut Self> {
        self.squeeze(External::new(NBytes::new(external_nbytes.into_inner().inner_mut())))
    }
}

// Implement &mut External<T> for any External<&mut T> implementation
impl<'a, T, F, OS> Squeeze<&'a mut External<T>> for Context<F, OS>
where
    Self: Squeeze<External<&'a mut T>>,
{
    fn squeeze(&mut self, external: &'a mut External<T>) -> Result<&mut Self> {
        self.squeeze(External::new(external.inner_mut()))
    }
}
