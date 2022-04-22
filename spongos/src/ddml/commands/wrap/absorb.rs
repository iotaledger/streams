use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{Wrap, Context},
            Absorb,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Bytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
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
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>  where T: AsRef<[u8]> {
        let bytes = bytes.as_ref();
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

impl<'a, F: PRP, T: AsRef<[u8]>, OS: io::OStream> Absorb<&'a NBytes<T>> for Context<F, OS> {
    fn absorb(&mut self, nbytes: &'a NBytes<T>) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream, T> Absorb<&'a Bytes<T>> for Context<F, OS> where T: AsRef<[u8]> {
    fn absorb(&mut self, bytes: &'a Bytes<T>) -> Result<&mut Self> {
        self.absorb(Size::new(bytes.len()))?;
        AbsorbContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F, T: 'a + AbsorbFallback<F>, OS> Absorb<&'a Fallback<T>> for Context<F, OS> {
//     fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
//         (val.0).wrap_absorb(self)?;
//         Ok(self)
//     }
// }
