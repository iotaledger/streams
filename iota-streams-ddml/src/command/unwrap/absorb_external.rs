use core::mem;

use super::Context;
use crate::{
    command::{
        wrap::Wrap,
        Absorb,
    },
    io,
    types::{
        AbsorbExternalFallback,
        ArrayLength,
        External,
        Fallback,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    Result,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

struct AbsorbExternalContext<F, IS> {
    ctx: Context<F, IS>,
}
impl<F, IS> AsMut<AbsorbExternalContext<F, IS>> for Context<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<F, IS> {
        unsafe { mem::transmute::<&'a mut Context<F, IS>, &'a mut AbsorbExternalContext<F, IS>>(self) }
    }
}
impl<F, IS> AsMut<Context<F, IS>> for AbsorbExternalContext<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, IS> {
        unsafe { mem::transmute::<&'a mut AbsorbExternalContext<F, IS>, &'a mut Context<F, IS>>(self) }
    }
}

impl<F: PRP, IS: io::IStream> Wrap for AbsorbExternalContext<F, IS> {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self> {
        self.ctx.spongos.absorb(&[u]);
        Ok(self)
    }
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

fn wrap_absorb_external_u8<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    u: Uint8,
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrap_u8(u.0)
}
fn wrap_absorb_external_u16<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    u: Uint16,
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrap_u16(u.0)
}
fn wrap_absorb_external_u32<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    u: Uint32,
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrap_u32(u.0)
}
fn wrap_absorb_external_u64<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    u: Uint64,
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrap_u64(u.0)
}
fn wrap_absorb_external_size<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    size: Size,
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrap_size(size)
}
fn wrap_absorb_external_bytes<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    bytes: &[u8],
) -> Result<&'a mut AbsorbExternalContext<F, IS>> {
    ctx.wrapn(bytes)
}

impl<'a, T: 'a, F: PRP, IS: io::IStream> Absorb<&'a External<T>> for Context<F, IS>
where
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a Uint8>> for Context<F, IS> {
    fn absorb(&mut self, u: External<&'a Uint8>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u8(self.as_mut(), *u.0)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<External<Uint8>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u8(self.as_mut(), u.0)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a Uint16>> for Context<F, IS> {
    fn absorb(&mut self, u: External<&'a Uint16>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u16(self.as_mut(), *u.0)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<External<Uint16>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u16(self.as_mut(), u.0)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a Uint32>> for Context<F, IS> {
    fn absorb(&mut self, u: External<&'a Uint32>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u32(self.as_mut(), *u.0)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<External<Uint32>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u32(self.as_mut(), u.0)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a Uint64>> for Context<F, IS> {
    fn absorb(&mut self, u: External<&'a Uint64>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u64(self.as_mut(), *u.0)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<External<Uint64>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u64(self.as_mut(), u.0)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a Size>> for Context<F, IS> {
    fn absorb(&mut self, size: External<&'a Size>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<External<Size>> for Context<F, IS> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> Absorb<External<&'a NBytes<N>>> for Context<F, IS> {
    fn absorb(&mut self, external_nbytes: External<&'a NBytes<N>>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_bytes(self.as_mut(), (external_nbytes.0).as_slice())?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a ed25519::PublicKey>> for Context<F, IS> {
    fn absorb(&mut self, pk: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_bytes(self.as_mut(), &pk.0.to_bytes()[..])?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<External<&'a x25519::PublicKey>> for Context<F, IS> {
    fn absorb(&mut self, pk: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_bytes(self.as_mut(), &pk.0.as_bytes()[..])?.as_mut())
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>, IS: io::IStream> Absorb<External<Fallback<&'a T>>> for Context<F, IS> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).unwrap_absorb_external(self)?;
        Ok(self)
    }
}
