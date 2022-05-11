use anyhow::Result;
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Mask,
        },
        io,
        types::{
            Bytes,
            Maybe,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

struct MaskContext<'a, F, OS> {
    ctx: &'a mut Context<F, OS>,
}

impl<'a, F, OS> MaskContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<F, OS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F: PRP, OS: io::OStream> Wrap for MaskContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        let mut slice = self.ctx.stream.try_advance(bytes.len())?;
        self.ctx.spongos.encrypt_mut(bytes, &mut slice)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<Uint8> for Context<F, OS> {
    fn mask(&mut self, u: Uint8) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<Uint16> for Context<F, OS> {
    fn mask(&mut self, u: Uint16) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<Uint32> for Context<F, OS> {
    fn mask(&mut self, u: Uint32) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<Uint64> for Context<F, OS> {
    fn mask(&mut self, u: Uint64) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<Size> for Context<F, OS> {
    fn mask(&mut self, size: Size) -> Result<&mut Self> {
        MaskContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T: AsRef<[u8]> + ?Sized, OS: io::OStream> Mask<NBytes<&'a T>> for Context<F, OS> {
    fn mask(&mut self, bytes: NBytes<&'a T>) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T, OS: io::OStream> Mask<&'a NBytes<T>> for Context<F, OS>
where
    Self: Mask<NBytes<&'a T>>,
{
    fn mask(&mut self, bytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.mask(NBytes::new(bytes.inner()))
    }
}

impl<'a, F: PRP, OS: io::OStream, T> Mask<Bytes<&'a T>> for Context<F, OS>
where
    T: AsRef<[u8]> + ?Sized,
{
    fn mask(&mut self, bytes: Bytes<&'a T>) -> Result<&mut Self> {
        self.mask(Size::new(bytes.len()))?;
        MaskContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream, T> Mask<&'a Bytes<T>> for Context<F, OS>
where
    Self: Mask<Bytes<&'a T>>,
{
    fn mask(&mut self, bytes: &'a Bytes<T>) -> Result<&mut Self> {
        self.mask(Bytes::new(bytes.inner()))
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a x25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a ed25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

impl<F, OS> Mask<&Spongos<F>> for Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, spongos: &Spongos<F>) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(spongos.outer())?.wrapn(spongos.inner())?;
        Ok(self)
    }
}

impl<F, OS, T> Mask<Maybe<Option<T>>> for Context<F, OS>
where
    Self: Mask<T> + Mask<Uint8>,
{
    fn mask(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            Some(t) => self.mask(Uint8::new(1))?.mask(t)?,
            None => self.mask(Uint8::new(0))?,
        };
        Ok(self)
    }
}
