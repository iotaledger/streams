// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;
use generic_array::ArrayLength;

// Local
use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{
                Context,
                Unwrap,
            },
            Skip,
        },
        io,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
    error::Error::PublicKeyGenerationFailure,
};
struct SkipContext<'a, F, IS> {
    ctx: &'a mut Context<F, IS>,
}

impl<'a, F, IS: io::IStream> SkipContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<F, IS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F, IS: io::IStream> Unwrap for SkipContext<'a, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>,
    {
        let bytes = bytes.as_mut();
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

impl<'a, F, T: AsMut<[u8]>, IS: io::IStream> Skip<NBytes<&'a mut T>> for Context<F, IS> {
    fn skip(&mut self, nbytes: NBytes<&'a mut T>) -> Result<&mut Self> {
        SkipContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F, T, IS: io::IStream> Skip<&'a mut NBytes<T>> for Context<F, IS>
where
    Self: Skip<NBytes<&'a mut T>>,
{
    fn skip(&mut self, nbytes: &'a mut NBytes<T>) -> Result<&mut Self> {
        self.skip(NBytes::new(nbytes.inner_mut()))
    }
}

impl<'a, F, IS: io::IStream> Skip<&'a mut Bytes<Vec<u8>>> for Context<F, IS> {
    fn skip(&mut self, bytes: &'a mut Bytes<Vec<u8>>) -> Result<&mut Self> {
        self.skip(Bytes::new(bytes.inner_mut()))
    }
}

impl<'a, F, IS: io::IStream> Skip<Bytes<&'a mut Vec<u8>>> for Context<F, IS> {
    fn skip(&mut self, mut bytes: Bytes<&'a mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.skip(&mut size)?;
        bytes.resize(size.inner());
        SkipContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}
