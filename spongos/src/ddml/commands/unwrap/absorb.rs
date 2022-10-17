// Rust
use alloc::vec::Vec;

// IOTA
use crypto::{keys::x25519, signatures::ed25519};

// Local
use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{Context, Unwrap},
            Absorb,
        },
        io,
        types::{Bytes, Maybe, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::{Error::PublicKeyGenerationFailure, Result},
};

/// A helper struct wrapper for performing [`Absorb`] operations with
struct AbsorbContext<'a, F: PRP, IS: io::IStream> {
    /// Internal [`Context`] that [`Absorb`] operations will be conducted on
    ctx: &'a mut Context<IS, F>,
}

/// Create a new [`AbsorbContext`] from the provided [`Context`].
impl<'a, F: PRP, IS: io::IStream> AbsorbContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<IS, F>) -> Self {
        Self { ctx }
    }
}

/// Retrieves bytes from [`Context`] stream and advances the read cursor. Then the `Context`
/// [`Spongos`] is used to decode the stream slice.
impl<F: PRP, IS: io::IStream> Unwrap for AbsorbContext<'_, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>,
    {
        let bytes = bytes.as_mut();
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        self.ctx.cursor += bytes.len();
        bytes.copy_from_slice(slice);
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

/// Reads a single byte encoded [`Uint8`] wrapper from [`Context`].
impl<F: PRP, IS: io::IStream> Absorb<&mut Uint8> for Context<IS, F> {
    fn absorb(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

/// Reads a two byte encoded [`Uint16`] wrapper from [`Context`].
impl<F: PRP, IS: io::IStream> Absorb<&mut Uint16> for Context<IS, F> {
    fn absorb(&mut self, u: &mut Uint16) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

/// Reads a four byte encoded [`Uint32`] wrapper from [`Context`].
impl<F: PRP, IS: io::IStream> Absorb<&mut Uint32> for Context<IS, F> {
    fn absorb(&mut self, u: &mut Uint32) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

/// Reads an eight byte encoded [`Uint64`] wrapper from [`Context`].
impl<F: PRP, IS: io::IStream> Absorb<&mut Uint64> for Context<IS, F> {
    fn absorb(&mut self, u: &mut Uint64) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

/// Reads an `n` byte encoded [`Size`] wrapper from [`Context`].
impl<F: PRP, IS: io::IStream> Absorb<&mut Size> for Context<IS, F> {
    fn absorb(&mut self, size: &mut Size) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

/// Reads a fixed sized [`NBytes`] wrapper from [`Context`]. `NBytes<bytes[n]>` is fixed-size and is
/// encoded with `n` bytes.
impl<F: PRP, T: AsMut<[u8]>, IS: io::IStream> Absorb<NBytes<T>> for Context<IS, F> {
    fn absorb(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

/// Reads a variable sized [`Bytes`] wrapper from [`Context`]. `Bytes<bytes[n]>` does not have a
/// known size, so first the [`Size`] `n` has to be decoded, and then `n` bytes are decoded.
impl<F: PRP, IS: io::IStream> Absorb<Bytes<&mut Vec<u8>>> for Context<IS, F> {
    fn absorb(&mut self, mut bytes: Bytes<&mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.absorb(&mut size)?;
        self.stream.ensure_size(size.inner())?;
        bytes.resize(size.inner());
        AbsorbContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}

/// Reads an Ed25519 public key from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut ed25519::PublicKey> for Context<IS, F> {
    fn absorb(&mut self, public_key: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; ed25519::PUBLIC_KEY_LENGTH];
        AbsorbContext::new(self).unwrapn(&mut bytes)?;
        match ed25519::PublicKey::try_from_bytes(bytes) {
            Ok(pk) => {
                *public_key = pk;
                Ok(self)
            }
            Err(e) => Err(PublicKeyGenerationFailure(e)),
        }
    }
}

/// Reads an X25519 public key from [`Context`].
impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut x25519::PublicKey> for Context<IS, F> {
    fn absorb(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; x25519::PUBLIC_KEY_LENGTH];
        AbsorbContext::new(self).unwrapn(&mut bytes)?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

/// Reads a [`Maybe`] wrapper for an `Option` from the [`Context`] stream. If the first `Uint8`
/// decoded is a `Uint8(1)`, then the `Option` is a `Some(T)`, and the content `T` is decoded next.
/// If it is a `Uint8(0)`, then the `Option` is a `None`.
impl<'a, F, IS, T> Absorb<Maybe<&'a mut Option<T>>> for Context<IS, F>
where
    for<'b> Self: Absorb<&'b mut T> + Absorb<&'b mut Uint8>,
    T: Default,
{
    fn absorb(&mut self, maybe: Maybe<&'a mut Option<T>>) -> Result<&mut Self> {
        let mut oneof = Uint8::default();
        let ctx = self.absorb(&mut oneof)?;
        if oneof.inner() == 1 {
            let mut t = T::default();
            ctx.absorb(&mut t)?;
            *maybe.into_inner() = Some(t);
        };
        Ok(self)
    }
}
