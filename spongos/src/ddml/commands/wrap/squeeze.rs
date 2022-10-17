use crate::{
    core::prp::PRP,
    ddml::{
        commands::{wrap::Context, Squeeze},
        io,
        modifiers::External,
        types::{Mac, NBytes},
    },
    error::Result,
};

/// Squeeze [`Context`] into a [`Mac`] length hash, using allocated space in context byte stream.
impl<'a, F: PRP, OS: io::OStream> Squeeze<&'a Mac> for Context<OS, F> {
    fn squeeze(&mut self, mac: &'a Mac) -> Result<&mut Self> {
        self.spongos.squeeze_mut(&mut self.stream.try_advance(mac.length())?);
        Ok(self)
    }
}

/// Squeeze [`Context`] into a [`Mac`] length hash, using allocated space in context byte stream.
impl<F: PRP, OS: io::OStream> Squeeze<Mac> for Context<OS, F> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}

/// Squeeze [`Context`] into an [`NBytes`] length hash.
impl<'a, F: PRP, T: AsMut<[u8]>, OS> Squeeze<External<&'a mut NBytes<T>>> for Context<OS, F> {
    fn squeeze(&mut self, external_nbytes: External<&'a mut NBytes<T>>) -> Result<&mut Self> {
        self.spongos.squeeze_mut(external_nbytes);
        Ok(self)
    }
}
