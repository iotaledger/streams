use core::mem;
use iota_streams_core::Result;

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
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

struct MaskContext<F, OS> {
    ctx: Context<F, OS>,
}
impl<F, OS> AsMut<MaskContext<F, OS>> for Context<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<F, OS> {
        unsafe { mem::transmute::<&'a mut Context<F, OS>, &'a mut MaskContext<F, OS>>(self) }
    }
}
impl<F, OS> AsMut<Context<F, OS>> for MaskContext<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, OS> {
        unsafe { mem::transmute::<&'a mut MaskContext<F, OS>, &'a mut Context<F, OS>>(self) }
    }
}

impl<F: PRP, OS: io::OStream> Wrap for MaskContext<F, OS> {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        slice[0] = u;
        self.ctx.spongos.encrypt_mut(slice);
        Ok(self)
    }
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(bytes.len())?;
        self.ctx.spongos.encrypt(bytes, &mut slice)?;
        Ok(self)
    }
}

fn wrap_mask_u8<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    u: Uint8,
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrap_u8(u.0)
}
fn wrap_mask_u16<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    u: Uint16,
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrap_u16(u.0)
}
fn wrap_mask_u32<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    u: Uint32,
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrap_u32(u.0)
}
fn wrap_mask_u64<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    u: Uint64,
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrap_u64(u.0)
}
fn wrap_mask_size<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    size: Size,
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrap_size(size)
}
fn wrap_mask_bytes<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut MaskContext<F, OS>,
    bytes: &[u8],
) -> Result<&'a mut MaskContext<F, OS>> {
    ctx.wrapn(bytes)
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Uint8> for Context<F, OS> {
    fn mask(&mut self, u: &'a Uint8) -> Result<&mut Self> {
        Ok(wrap_mask_u8(self.as_mut(), *u)?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Uint16> for Context<F, OS> {
    fn mask(&mut self, u: &'a Uint16) -> Result<&mut Self> {
        Ok(wrap_mask_u16(self.as_mut(), *u)?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Uint32> for Context<F, OS> {
    fn mask(&mut self, u: &'a Uint32) -> Result<&mut Self> {
        Ok(wrap_mask_u32(self.as_mut(), *u)?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Uint64> for Context<F, OS> {
    fn mask(&mut self, u: &'a Uint64) -> Result<&mut Self> {
        Ok(wrap_mask_u64(self.as_mut(), *u)?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Size> for Context<F, OS> {
    fn mask(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_mask_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> Mask<&'a NBytes<N>> for Context<F, OS> {
    fn mask(&mut self, nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        Ok(wrap_mask_bytes(self.as_mut(), nbytes.as_slice())?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a Bytes> for Context<F, OS> {
    fn mask(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        let size = Size((bytes.0).len());
        self.mask(&size)?;
        Ok(wrap_mask_bytes(self.as_mut(), &(bytes.0)[..])?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a x25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_mask_bytes(self.as_mut(), &pk.as_bytes()[..])?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Mask<&'a ed25519::PublicKey> for Context<F, OS> {
    fn mask(&mut self, pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_mask_bytes(self.as_mut(), &pk.to_bytes()[..])?.as_mut())
    }
}
