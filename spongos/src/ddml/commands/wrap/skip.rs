use generic_array::ArrayLength;
use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Skip,
        },
        io,
        modifiers::External,
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
};

struct SkipContext<'a, F, OS> {
    ctx: &'a mut Context<F, OS>,
}

impl<'a, F, OS> SkipContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<F, OS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F, OS: io::OStream> Wrap for SkipContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self> where T: AsRef<[u8]> {
        let bytes = bytes.as_ref();
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

impl<F, OS: io::OStream> Skip<Uint8> for Context<F, OS> {
    fn skip(&mut self, u: Uint8) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

impl<'a, F, OS: io::OStream> Skip<Uint16> for Context<F, OS> {
    fn skip(&mut self, u: Uint16) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

impl<'a, F, OS: io::OStream> Skip<Uint32> for Context<F, OS> {
    fn skip(&mut self, u: Uint32) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

impl<'a, F, OS: io::OStream> Skip<Uint64> for Context<F, OS> {
    fn skip(&mut self, u: Uint64) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

impl<'a, F, OS: io::OStream> Skip<Size> for Context<F, OS> {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        SkipContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F, T: AsRef<[u8]>, OS: io::OStream> Skip<NBytes<&'a T>> for Context<F, OS> {
    fn skip(&mut self, bytes: NBytes<&'a T>) -> Result<&mut Self> {
        SkipContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F, T, OS: io::OStream> Skip<&'a NBytes<T>> for Context<F, OS> where Self: Skip<NBytes<&'a T>> {
    fn skip(&mut self, bytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.skip(NBytes::new(bytes.inner()))
    }
}

impl<'a, F, OS: io::OStream, T> Skip<&'a Bytes<T>> for Context<F, OS> where T: AsRef<[u8]> {
    fn skip(&mut self, bytes: &'a Bytes<T>) -> Result<&mut Self> {
        self.skip(Size::new(bytes.len()))?;
        SkipContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F, T: 'a + SkipFallback<F>, OS: io::OStream> Skip<&'a Fallback<T>> for Context<F, OS> {
//     fn skip(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
//         (val.0).wrap_skip(self)?;
//         Ok(self)
//     }
// }
