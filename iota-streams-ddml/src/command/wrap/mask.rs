use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use iota_streams_core::{
    sponge::prp::PRP,
    Result,
};

use super::{
    wrap::*,
    Context,
};
use crate::{
    command::Mask,
    io,
    types::{
        ArrayLength,
        Bytes,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
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
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(bytes.len())?;
        self.ctx.spongos.encrypt(bytes, &mut slice)?;
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

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> Mask<&'a NBytes<N>> for Context<F, OS> {
    fn mask(&mut self, bytes: &'a NBytes<N>) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(bytes.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Bytes> for Context<F, OS> {
    fn mask(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.mask(Size(bytes.len()))?;
        MaskContext::new(self).wrapn(bytes.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a x25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a ed25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key.as_slice())?;
        Ok(self)
    }
}
