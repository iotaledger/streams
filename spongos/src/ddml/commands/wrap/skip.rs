use crate::{
    ddml::{
        commands::{
            wrap::{Context, Wrap},
            Skip,
        },
        io,
        types::{Bytes, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// A helper struct wrapper for performing [`Skip`] operations with
struct SkipContext<'a, F, OS> {
    /// Internal [`Context`] that [`Skip`] operations will be conducted on
    ctx: &'a mut Context<OS, F>,
}

/// Create a new [`SkipContext`] from the provided [`Context`].
impl<'a, F, OS> SkipContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<OS, F>) -> Self {
        Self { ctx }
    }
}

/// Absorb `n` bytes into the [`Context`] stream without using spongos operations
impl<'a, F, OS: io::OStream> Wrap for SkipContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

/// Skipped values are just encoded and do not affect [`Context`] spongos state.
/// All Uint8 values are encoded with 1 byte
impl<F, OS: io::OStream> Skip<Uint8> for Context<OS, F> {
    fn skip(&mut self, u: Uint8) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

/// Skipped values are just encoded and do not affect [`Context`] spongos state.
/// All Uint16 values are encoded with 2 bytes
impl<F, OS: io::OStream> Skip<Uint16> for Context<OS, F> {
    fn skip(&mut self, u: Uint16) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

/// Skipped values are just encoded and do not affect [`Context`] spongos state.
/// All Uint32 values are encoded with 4 bytes
impl<F, OS: io::OStream> Skip<Uint32> for Context<OS, F> {
    fn skip(&mut self, u: Uint32) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

/// Skipped values are just encoded and do not affect [`Context`] spongos state.
/// All Uint64 values are encoded with 8 bytes
impl<F, OS: io::OStream> Skip<Uint64> for Context<OS, F> {
    fn skip(&mut self, u: Uint64) -> Result<&mut Self> {
        SkipContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

/// Encodes an `n` byte encoded [`Size`] wrapper into [`Context`].
impl<F, OS: io::OStream> Skip<Size> for Context<OS, F> {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        SkipContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

/// Encodes an `n` byte encoded [`NBytes`] wrapper into [`Context`].
/// `NByte<bytes[n]>` is fixed-size and is encoded with `n` bytes.
impl<F, T: AsRef<[u8]>, OS: io::OStream> Skip<NBytes<T>> for Context<OS, F> {
    fn skip(&mut self, bytes: NBytes<T>) -> Result<&mut Self> {
        SkipContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

/// Encodes an `n` byte encoded [`Bytes`] wrapper into [`Context`].
/// `Bytes<bytes[n]>` has variable size thus the size `n` is encoded before the content bytes.
impl<F, OS: io::OStream, T> Skip<Bytes<T>> for Context<OS, F>
where
    T: AsRef<[u8]>,
{
    fn skip(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        self.skip(Size::new(bytes.len()))?;
        SkipContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}
