use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::Context,
            Squeeze,
        },
        io,
        modifiers::External,
        types::{
            Mac,
            NBytes,
        },
    },
};

/// External values are not encoded.
impl<'a, F: PRP, OS: io::OStream> Squeeze<&'a Mac> for Context<OS, F> {
    fn squeeze(&mut self, mac: &'a Mac) -> Result<&mut Self> {
        self.spongos.squeeze_mut(&mut self.stream.try_advance(mac.length())?);
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Squeeze<Mac> for Context<OS, F> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

impl<'a, F: PRP, T: AsMut<[u8]>, OS> Squeeze<External<NBytes<&'a mut T>>> for Context<OS, F> {
    fn squeeze(&mut self, external_nbytes: External<NBytes<&'a mut T>>) -> Result<&mut Self> {
        self.spongos.squeeze_mut(external_nbytes);
        Ok(self)
    }
}

impl<'a, F: PRP, T, OS> Squeeze<External<&'a mut NBytes<T>>> for Context<OS, F>
where
    Self: Squeeze<External<NBytes<&'a mut T>>>,
{
    fn squeeze(&mut self, external_nbytes: External<&'a mut NBytes<T>>) -> Result<&mut Self> {
        self.squeeze(External::new(NBytes::new(external_nbytes.into_inner().inner_mut())))
    }
}

// Implement &mut External<T> for any External<&mut T> implementation
impl<'a, T, F, OS> Squeeze<&'a mut External<T>> for Context<OS, F>
where
    Self: Squeeze<External<&'a mut T>>,
{
    fn squeeze(&mut self, external: &'a mut External<T>) -> Result<&mut Self> {
        self.squeeze(External::new(external.inner_mut()))
    }
}
