use iota_streams_core::Result;

use super::{
    unwrap::Unwrap,
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

struct SkipContext<'a, F, IS> {
    ctx: &'a mut Context<F, IS>,
}

impl<'a, F, IS> SkipContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<F, IS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F, IS: io::IStream> Unwrap for SkipContext<'a, F, IS> {
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        bytes.copy_from_slice(slice);
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint8> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        SkipContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint16> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        SkipContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint32> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        SkipContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Uint64> for Context<F, IS> {
    fn skip(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        SkipContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Size> for Context<F, IS> {
    fn skip(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        SkipContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F, N: ArrayLength<u8>, IS: io::IStream> Skip<&'a mut NBytes<N>> for Context<F, IS> {
    fn skip(&mut self, nbytes: &'a mut NBytes<N>) -> Result<&mut Self> {
        SkipContext::new(self).unwrapn(nbytes.as_mut_slice())?;
        Ok(self)
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Bytes> for Context<F, IS> {
    fn skip(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.skip(&mut size)?;
        (bytes.0).resize(size.0, 0);
        SkipContext::new(self).unwrapn(bytes.as_mut_slice())?;
        Ok(self)
    }
}

impl<'a, F, T: 'a + SkipFallback<F>, IS: io::IStream> Skip<&'a mut Fallback<T>> for Context<F, IS> {
    fn skip(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
        (val.0).unwrap_skip(self)?;
        Ok(self)
    }
}
