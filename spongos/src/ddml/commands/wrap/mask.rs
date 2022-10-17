use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    core::{prp::PRP, spongos::Spongos},
    ddml::{
        commands::{
            wrap::{Context, Wrap},
            Mask,
        },
        io,
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// A helper struct wrapper for performing [`Mask`] operations with
struct MaskContext<'a, F, OS> {
    /// Internal [`Context`] that [`Mask`] operations will be conducted on
    ctx: &'a mut Context<OS, F>,
}

/// Create a new [`MaskContext`] from the provided [`Context`].
impl<'a, F, OS> MaskContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<OS, F>) -> Self {
        Self { ctx }
    }
}

/// Encrypts bytes into the [`Context`] spongos, and advances the stream by the provided bytes
/// length, copying those bytes into the stream.
impl<'a, F: PRP, OS: io::OStream> Wrap for MaskContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        let mut slice = self.ctx.stream.try_advance(bytes.len())?;
        self.ctx.spongos.encrypt_mut(bytes, &mut slice)?;
        Ok(self)
    }
}

/// Encrypts a single byte encoded [`Uint8`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Mask<Uint8> for Context<OS, F> {
    fn mask(&mut self, u: Uint8) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

/// Encrypts a two byte encoded [`Uint16`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Mask<Uint16> for Context<OS, F> {
    fn mask(&mut self, u: Uint16) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

/// Encrypts a four byte encoded [`Uint32`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Mask<Uint32> for Context<OS, F> {
    fn mask(&mut self, u: Uint32) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

/// Encrypts an eight byte encoded [`Uint64`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Mask<Uint64> for Context<OS, F> {
    fn mask(&mut self, u: Uint64) -> Result<&mut Self> {
        MaskContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

/// Encrypts an `n` byte encoded [`Size`] wrapper into [`Context`].
impl<F: PRP, OS: io::OStream> Mask<Size> for Context<OS, F> {
    fn mask(&mut self, size: Size) -> Result<&mut Self> {
        MaskContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

/// Encrypts a variable sized [`NBytes`] wrapper into [`Context`].
/// `NByte<bytes[n]>` is fixed-size and is encoded with `n` bytes.
impl<F: PRP, T: AsRef<[u8]>, OS: io::OStream> Mask<NBytes<T>> for Context<OS, F> {
    fn mask(&mut self, bytes: NBytes<T>) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

/// Encrypts a variable sized [`Bytes`] wrapper into [`Context`]. `Bytes<bytes[n]>` has variable
/// size thus the size `n` is encoded before the content bytes are wrapped.
impl<F: PRP, OS: io::OStream, T> Mask<Bytes<T>> for Context<OS, F>
where
    T: AsRef<[u8]>,
{
    fn mask(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        self.mask(Size::new(bytes.len()))?;
        MaskContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

/// Encrypts an Ed25519 public key into [`Context`].
impl<'a, F: PRP, OS: io::OStream> Mask<&'a x25519::PublicKey> for Context<OS, F> {
    fn mask(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

/// Encrypts an X25519 public key into [`Context`].
impl<'a, F: PRP, OS: io::OStream> Mask<&'a ed25519::PublicKey> for Context<OS, F> {
    fn mask(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

/// Encrypts an explicit [`Spongos`] state into [`Context`].
impl<OS, F> Mask<&Spongos<F>> for Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, spongos: &Spongos<F>) -> Result<&mut Self> {
        MaskContext::new(self).wrapn(spongos.outer())?.wrapn(spongos.inner())?;
        Ok(self)
    }
}

/// Encrypts a [`Maybe`] wrapper for an `Option` into the [`Context`] size. If the `Option` is
/// `Some`, a `Uint8(1)` value is encrypted first, followed by the content. If the `Option` is
/// `None`, only a `Uint8(0)` is encrypted.
impl<F, OS, T> Mask<Maybe<Option<T>>> for Context<OS, F>
where
    Self: Mask<T> + Mask<Uint8>,
{
    fn mask(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            Some(t) => self.mask(Uint8::new(1))?.mask(t)?,
            None => self.mask(Uint8::new(0))?,
        };
        Ok(self)
    }
}
