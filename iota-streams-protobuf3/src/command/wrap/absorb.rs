use anyhow::Result;
use core::mem;

use super::{
    wrap::*,
    Context,
};
use crate::{
    command::Absorb,
    io,
    types::{
        AbsorbFallback,
        Bytes,
        Fallback,
        NBytes,
        Size,
        Uint8,
    },
};
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

struct AbsorbContext<F, OS> {
    ctx: Context<F, OS>,
}
impl<F, OS> AsMut<AbsorbContext<F, OS>> for Context<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<F, OS> {
        unsafe { mem::transmute::<&'a mut Context<F, OS>, &'a mut AbsorbContext<F, OS>>(self) }
    }
}
impl<F, OS> AsMut<Context<F, OS>> for AbsorbContext<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, OS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<F, OS>, &'a mut Context<F, OS>>(self) }
    }
}

impl<F, OS: io::OStream> Wrap for AbsorbContext<F, OS>
where
    F: PRP,
{
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        slice[0] = u;
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ctx.spongos.absorb(bytes);
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

fn wrap_absorb_u8<'a, F, OS: io::OStream>(
    ctx: &'a mut AbsorbContext<F, OS>,
    u: Uint8,
) -> Result<&'a mut AbsorbContext<F, OS>>
where
    F: PRP,
{
    ctx.wrap_u8(u.0)
}
fn wrap_absorb_size<'a, F, OS: io::OStream>(
    ctx: &'a mut AbsorbContext<F, OS>,
    size: Size,
) -> Result<&'a mut AbsorbContext<F, OS>>
where
    F: PRP,
{
    wrap_size(ctx, size)
}
fn wrap_absorb_bytes<'a, F, OS: io::OStream>(
    ctx: &'a mut AbsorbContext<F, OS>,
    bytes: &[u8],
) -> Result<&'a mut AbsorbContext<F, OS>>
where
    F: PRP,
{
    ctx.wrapn(bytes)
}

impl<'a, F, OS: io::OStream> Absorb<&'a Uint8> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, u: &'a Uint8) -> Result<&mut Self> {
        Ok(wrap_absorb_u8(self.as_mut(), *u)?.as_mut())
    }
}

impl<F, OS: io::OStream> Absorb<Uint8> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

impl<'a, F, OS: io::OStream> Absorb<&'a Size> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_absorb_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<F, OS: io::OStream> Absorb<Size> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, F, OS: io::OStream> Absorb<&'a NBytes> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, nbytes: &'a NBytes) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), &(nbytes.0)[..])?.as_mut())
    }
}

impl<'a, F, OS: io::OStream> Absorb<&'a Bytes> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.absorb(Size((bytes.0).len()))?;
        Ok(wrap_absorb_bytes(self.as_mut(), &(bytes.0)[..])?.as_mut())
    }
}

impl<'a, F, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), &pk.to_bytes()[..])?.as_mut())
    }
}

impl<'a, F, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<F, OS>
where
    F: PRP,
{
    fn absorb(&mut self, pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), &pk.as_bytes()[..])?.as_mut())
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, OS: io::OStream> Absorb<&'a Fallback<T>> for Context<F, OS> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).wrap_absorb(self)?;
        Ok(self)
    }
}
