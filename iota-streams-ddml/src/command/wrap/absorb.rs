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
    command::Absorb,
    io,
    types::{
        AbsorbFallback,
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

struct AbsorbContext<'a, F, OS> {
    ctx: &'a mut Context<F, OS>,
}

impl<'a, F, OS> AbsorbContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<F, OS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F: PRP, OS: io::OStream> Wrap for AbsorbContext<'a, F, OS> {
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ctx.spongos.absorb(bytes);
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint8> for Context<F, OS> {
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint16> for Context<F, OS> {
    fn absorb(&mut self, u: Uint16) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint32> for Context<F, OS> {
    fn absorb(&mut self, u: Uint32) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint64> for Context<F, OS> {
    fn absorb(&mut self, u: Uint64) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Size> for Context<F, OS> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> Absorb<&'a NBytes<N>> for Context<F, OS> {
    fn absorb(&mut self, nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(nbytes.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Bytes> for Context<F, OS> {
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.absorb(Size(bytes.len()))?;
        AbsorbContext::new(self).wrapn(bytes.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key.as_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key.as_slice())?;
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, OS: io::OStream> Absorb<&'a Fallback<T>> for Context<F, OS> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).wrap_absorb(self)?;
        Ok(self)
    }
}
