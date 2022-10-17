// Rust
use alloc::vec::Vec;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};

// Local
use crate::{
    core::{prp::PRP, spongos::Spongos},
    ddml::{
        commands::{
            unwrap::{Context, Unwrap},
            Mask,
        },
        io,
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::{Error::PublicKeyGenerationFailure, Result},
};

/// A helper struct wrapper for performing [`Mask`] operations with
struct MaskContext<'a, F, IS> {
    /// Internal [`Context`] that [`Mask`] operations will be conducted on
    ctx: &'a mut Context<IS, F>,
}

/// Create a new [`MaskContext`] from the provided [`Context`].
impl<'a, F: PRP, IS: io::IStream> MaskContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<IS, F>) -> Self {
        Self { ctx }
    }
}

/// Decrypts bytes from the [`Context`] spongos, and advances the stream by the provided bytes
/// length, copying those bytes into the stream.
impl<F: PRP, IS: io::IStream> Unwrap for MaskContext<'_, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>,
    {
        let y = self.ctx.stream.try_advance(bytes.as_mut().len())?;
        self.ctx.cursor += bytes.as_mut().len();
        self.ctx.spongos.decrypt_mut(y, &mut bytes)?;
        Ok(self)
    }
}

/// Decrypts a single byte encoded [`Uint8`] wrapper from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint8> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

/// Decrypts a two byte encoded [`Uint16`] wrapper from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint16> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

/// Decrypts a four byte encoded [`Uint32`] wrapper from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint32> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

/// Decrypts an eight byte encoded [`Uint64`] wrapper from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint64> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

/// Decrypts an `n` byte encoded [`Size`] wrapper from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Size> for Context<IS, F> {
    fn mask(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

/// Decrypts a fixed sized [`NBytes`] wrapper from [`Context`]. `NBytes<bytes[n]>` is fixed-size and
/// is decoded with `n` bytes.
impl<F: PRP, T: AsMut<[u8]>, IS: io::IStream> Mask<NBytes<T>> for Context<IS, F> {
    fn mask(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        MaskContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

/// Decrypts a variable sized [`Bytes`] wrapper from [`Context`]. `Bytes<bytes[n]>` does not have a
/// known size, so first the [`Size`] `n` has to be decrypted, and then `n` bytes are decrypted.
impl<'a, F: PRP, IS: io::IStream> Mask<Bytes<&'a mut Vec<u8>>> for Context<IS, F> {
    fn mask(&mut self, mut bytes: Bytes<&'a mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.mask(&mut size)?;
        self.stream.ensure_size(size.inner())?;
        bytes.resize(size.inner());
        MaskContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}

/// Decrypts an X25519 public key from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut x25519::PublicKey> for Context<IS, F> {
    fn mask(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; x25519::PUBLIC_KEY_LENGTH];
        MaskContext::new(self).unwrapn(&mut bytes)?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

/// Decrypts an Ed25519 public key from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut ed25519::PublicKey> for Context<IS, F> {
    fn mask(&mut self, public_key: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; ed25519::PUBLIC_KEY_LENGTH];
        MaskContext::new(self).unwrapn(&mut bytes)?;
        match ed25519::PublicKey::try_from_bytes(bytes) {
            Ok(pk) => {
                *public_key = pk;
                Ok(self)
            }
            Err(e) => Err(PublicKeyGenerationFailure(e)),
        }
    }
}

/// Decrypts [`Context`] state into an explicit [`Spongos`].
impl<IS, F> Mask<&mut Spongos<F>> for Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, spongos: &mut Spongos<F>) -> Result<&mut Self> {
        MaskContext::new(self)
            .unwrapn(spongos.outer_mut())?
            .unwrapn(spongos.inner_mut())?;
        Ok(self)
    }
}

/// Decrypts a [`Maybe`] wrapper for an `Option` from the [`Context`] stream. If the first `Uint8`
/// decrypted is a `Uint8(1)`, then the `Option` is a `Some(T)`, and the content `T` is decrypted
/// next. If it is a `Uint8(0)`, then the `Option` is a `None`.
impl<'a, F, IS, T> Mask<Maybe<&'a mut Option<T>>> for Context<IS, F>
where
    for<'b> Self: Mask<&'b mut T> + Mask<&'b mut Uint8>,
    T: Default,
{
    fn mask(&mut self, maybe: Maybe<&'a mut Option<T>>) -> Result<&mut Self> {
        let mut oneof = Uint8::default();
        let ctx = self.mask(&mut oneof)?;
        if oneof.inner() == 1 {
            let mut t = T::default();
            ctx.mask(&mut t)?;
            *maybe.into_inner() = Some(t);
        };
        Ok(self)
    }
}
