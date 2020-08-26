use anyhow::{
    bail,
    Result,
};
use core::mem;

use super::{
    unwrap::*,
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

struct AbsorbContext<F, IS> {
    ctx: Context<F, IS>,
}
impl<F, IS> AsMut<AbsorbContext<F, IS>> for Context<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<F, IS> {
        unsafe { mem::transmute::<&'a mut Context<F, IS>, &'a mut AbsorbContext<F, IS>>(self) }
    }
}
impl<F, IS> AsMut<Context<F, IS>> for AbsorbContext<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, IS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<F, IS>, &'a mut Context<F, IS>>(self) }
    }
}

impl<F, IS: io::IStream> Unwrap for AbsorbContext<F, IS>
where
    F: PRP,
{
    fn unwrap_u8(&mut self, u: &mut u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        *u = slice[0];
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        bytes.copy_from_slice(slice);
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

fn unwrap_absorb_u8<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    u: &mut Uint8,
) -> Result<&'a mut AbsorbContext<F, IS>>
where
    F: PRP,
{
    ctx.unwrap_u8(&mut u.0)
}
fn unwrap_absorb_size<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    size: &mut Size,
) -> Result<&'a mut AbsorbContext<F, IS>>
where
    F: PRP,
{
    unwrap_size(ctx, size)
}
fn unwrap_absorb_bytes<'a, F, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    bytes: &mut [u8],
) -> Result<&'a mut AbsorbContext<F, IS>>
where
    F: PRP,
{
    ctx.unwrapn(bytes)
}

impl<F, IS: io::IStream> Absorb<&mut Uint8> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        Ok(unwrap_absorb_u8(self.as_mut(), u)?.as_mut())
    }
}

impl<F, IS: io::IStream> Absorb<&mut Size> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, size: &mut Size) -> Result<&mut Self> {
        Ok(unwrap_absorb_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<&'a mut NBytes> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, nbytes: &'a mut NBytes) -> Result<&mut Self> {
        Ok(unwrap_absorb_bytes(self.as_mut(), &mut (nbytes.0)[..])?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<&'a mut Bytes> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.absorb(&mut size)?;
        (bytes.0).resize(size.0, 0);
        Ok(unwrap_absorb_bytes(self.as_mut(), &mut (bytes.0)[..])?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Absorb<&'a mut ed25519::PublicKey> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, pk: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut pk_bytes = [0_u8; 32];
        unwrap_absorb_bytes(self.as_mut(), &mut pk_bytes)?;
        match ed25519::PublicKey::from_bytes(&pk_bytes) {
            Ok(apk) => *pk = apk,
            Err(err) => bail!("Bad ed25519 public key: {}", err),
        }
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Absorb<&'a mut x25519::PublicKey> for Context<F, IS>
where
    F: PRP,
{
    fn absorb(&mut self, pk: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut pk_bytes = [0_u8; 32];
        unwrap_absorb_bytes(self.as_mut(), &mut pk_bytes)?;
        *pk = x25519::PublicKey::from(pk_bytes);
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, IS: io::IStream> Absorb<&'a mut Fallback<T>> for Context<F, IS> {
    fn absorb(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
        (val.0).unwrap_absorb(self)?;
        Ok(self)
    }
}
