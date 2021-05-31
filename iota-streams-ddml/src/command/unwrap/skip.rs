use core::mem;
use iota_streams_core::Result;

use super::{
    unwrap::*,
    Context,
};
use crate::{
    command::Skip,
    io,
    types::{
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        SkipFallback,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

struct SkipContext<F, IS> {
    ctx: Context<F, IS>,
}
impl<F, IS> AsMut<SkipContext<F, IS>> for Context<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<F, IS> {
        unsafe { mem::transmute::<&'a mut Context<F, IS>, &'a mut SkipContext<F, IS>>(self) }
    }
}
impl<F, IS> AsMut<Context<F, IS>> for SkipContext<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, IS> {
        unsafe { mem::transmute::<&'a mut SkipContext<F, IS>, &'a mut Context<F, IS>>(self) }
    }
}

impl<F, IS: io::IStream> Unwrap for SkipContext<F, IS> {
    fn unwrap_u8(&mut self, u: &mut u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        *u = slice[0];
        Ok(self)
    }
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        bytes.copy_from_slice(slice);
        Ok(self)
    }
}

fn unwrap_skip_u8<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    u: &mut Uint8,
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrap_u8(&mut u.0)
}
fn unwrap_skip_u16<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    u: &mut Uint16,
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrap_u16(&mut u.0)
}
fn unwrap_skip_u32<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    u: &mut Uint32,
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrap_u32(&mut u.0)
}
fn unwrap_skip_u64<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    u: &mut Uint64,
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrap_u64(&mut u.0)
}
fn unwrap_skip_size<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    size: &mut Size,
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrap_size(size)
}
fn unwrap_skip_bytes<'a, F, IS: io::IStream>(
    ctx: &'a mut SkipContext<F, IS>,
    bytes: &mut [u8],
) -> Result<&'a mut SkipContext<F, IS>> {
    ctx.unwrapn(bytes)
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint8> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        Ok(unwrap_skip_u8(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint16> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        Ok(unwrap_skip_u16(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint32> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        Ok(unwrap_skip_u32(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint64> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        Ok(unwrap_skip_u64(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Size> for Context<F, IS> {
    fn skip(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        Ok(unwrap_skip_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, F, N: ArrayLength<u8>, IS: io::IStream> Skip<&'a mut NBytes<N>> for Context<F, IS> {
    fn skip(&mut self, nbytes: &'a mut NBytes<N>) -> Result<&mut Self> {
        Ok(unwrap_skip_bytes(self.as_mut(), nbytes.as_mut_slice())?.as_mut())
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Bytes> for Context<F, IS> {
    fn skip(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.skip(&mut size)?;
        (bytes.0).resize(size.0, 0);
        Ok(unwrap_skip_bytes(self.as_mut(), &mut (bytes.0)[..])?.as_mut())
    }
}

impl<'a, F, T: 'a + SkipFallback<F>, IS: io::IStream> Skip<&'a mut Fallback<T>> for Context<F, IS> {
    fn skip(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
        (val.0).unwrap_skip(self)?;
        Ok(self)
    }
}
