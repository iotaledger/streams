use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{Context, Wrap},
            Absorb,
        },
        io,
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// A helper struct wrapper for performing [`Absorb`] operations with
struct AbsorbContext<'a, F, OS> {
    /// Internal [`Context`] that [`Absorb`] operations will be conducted on
    ctx: &'a mut Context<OS, F>,
}

/// Create a new [`AbsorbContext`] from the provided [`Context`].
impl<'a, F, OS> AbsorbContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<OS, F>) -> Self {
        Self { ctx }
    }
}

/// Encode bytes into the [`Context`] spongos, and advances the stream by the provided bytes length,
/// copying those bytes into the stream.
impl<'a, F: PRP, OS: io::OStream> Wrap for AbsorbContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        self.ctx.spongos.absorb(bytes);
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

/// Absorbs a single byte encoded [`Uint8`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Absorb<Uint8> for Context<OS, F> {
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

/// Absorbs a two byte encoded [`Uint16`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Absorb<Uint16> for Context<OS, F> {
    fn absorb(&mut self, u: Uint16) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

/// Absorbs a four byte encoded [`Uint32`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Absorb<Uint32> for Context<OS, F> {
    fn absorb(&mut self, u: Uint32) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

/// Absorbs an eight byte encoded [`Uint64`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Absorb<Uint64> for Context<OS, F> {
    fn absorb(&mut self, u: Uint64) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

/// Absorbs an `n` byte encoded [`Size`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Absorb<Size> for Context<OS, F> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

/// Absorbs a fixed sized [`NBytes`] wrapper into [`Context`]. `NBytes<bytes[n]>` is fixed-size and
/// is encoded with `n` bytes.
impl<F, T, OS> Absorb<NBytes<T>> for Context<OS, F>
where
    F: PRP,
    T: AsRef<[u8]>,
    OS: io::OStream,
{
    fn absorb(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(nbytes)?;
        Ok(self)
    }
}

/// Absorbs a variable sized [`Bytes`] wrapper into [`Context`]. `Bytes<bytes[n]>` has variable size
/// thus the size `n` is encoded before the content bytes are wrapped.
impl<F: PRP, OS: io::OStream, T> Absorb<Bytes<T>> for Context<OS, F>
where
    T: AsRef<[u8]>,
{
    fn absorb(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        self.absorb(Size::new(bytes.len()))?;
        AbsorbContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

/// Absorbs an Ed25519 public key into [`Context`].
impl<'a, F: PRP, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<OS, F> {
    fn absorb(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

/// Absorbs an X25519 public key into [`Context`].
impl<'a, F: PRP, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<OS, F> {
    fn absorb(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

/// Absorbs a [`Maybe`] wrapper for an `Option` into the [`Context`] stream. If the `Option` is
/// `Some`, a `Uint8(1)` value is absorbed first, followed by the content. If the `Option` is
/// `None`, only a `Uint8(0)` is absorbed.
impl<F, OS, T> Absorb<Maybe<Option<T>>> for Context<OS, F>
where
    Self: Absorb<T> + Absorb<Uint8>,
{
    fn absorb(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            Some(t) => self.absorb(Uint8::new(1))?.absorb(t)?,
            None => self.absorb(Uint8::new(0))?,
        };
        Ok(self)
    }
}
