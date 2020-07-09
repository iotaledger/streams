use anyhow::{
    Result,
};
use std::mem;

use super::Context;
use crate::{
    command::{
        wrap::{
            wrap_size,
            Wrap,
        },
        Absorb,
    },
    io,
    types::{
        AbsorbExternalFallback,
        External,
        Fallback,
        NBytes,
        Size,
        Uint8,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
};
use iota_streams_core_edsig::{signature::ed25519, key_exchange::x25519};

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

impl<F, IS: io::IStream> Wrap for AbsorbExternalContext<F, IS>
where
    F: PRP,
{
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self> {
        self.ctx.spongos.absorb(&[u]);
        Ok(self)
    }
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

fn wrap_absorb_external_u8<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    u: Uint8,
) -> Result<&'a mut AbsorbExternalContext<F, IS>>
where
    F: PRP,
{
    ctx.wrap_u8(u.0)
}
fn wrap_absorb_external_size<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    size: Size,
) -> Result<&'a mut AbsorbExternalContext<F, IS>>
where
    F: PRP,
{
    wrap_size(ctx, size)
}
fn wrap_absorb_external_bytes<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbExternalContext<F, IS>,
    bytes: &[u8],
) -> Result<&'a mut AbsorbExternalContext<F, IS>>
where
    F: PRP,
{
    ctx.wrapn(bytes)
}

impl<'a, T: 'a, F, IS: io::IStream> Absorb<&'a External<T>> for Context<F, IS>
where
    F: PRP,
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, F, IS: io::IStream> Absorb<External<&'a Uint8>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, u: External<&'a Uint8>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_u8(self.as_mut(), *u.0)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<External<&'a Size>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, size: External<&'a Size>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<F, IS: io::IStream> Absorb<External<Size>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, F, IS: io::IStream> Absorb<External<&'a NBytes>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, external_ntrytes: External<&'a NBytes>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_bytes(self.as_mut(), &((external_ntrytes.0).0)[..])?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<External<&'a ed25519::PublicKey>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, _pk: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        panic!("not implemented");
        //Ok(wrap_absorb_external_bytes(self.as_mut(), &pk)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<External<&'a x25519::PublicKey>> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, _pk: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        panic!("not implemented");
        //TODO: validate pk
        //Ok(wrap_absorb_external_bytes(self.as_mut(), &mut pk)?.as_mut())
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>, IS: io::IStream> Absorb<External<Fallback<&'a T>>>
    for Context<F, IS>
{
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).unwrap_absorb_external(self)?;
        Ok(self)
    }
}
